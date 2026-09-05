import asyncio
import os
import re
import shlex
from typing import Dict, Any, List, Tuple
from agent_core_utils import track_latency, audit_logger

HIGHRISKCOMMANDS = {"rm", "rmdir", "chmod", "chown", "sudo", "dd", "mkfs"}

# 1. Long-running interactive daemons & dev servers across all major tech stacks
BLOCKED_DAEMONS = [
    # MCP (Model Context Protocol) Daemons
    r"\b(npx\s+)?ng\s+mcp(?!\s+--help)\b",
    r"\b(uvx\s+|npx\s+)?mcp-server-.*\b",
    
    # Android / Gradle / Kotlin
    r"\b(gradlew?|./gradlew)\s+.*(run|app:run|connectedCheck)\b",
    r"\b(adb)\s+(logcat|shell|wait-for-device)\b",
    
    # iOS / Xcode
    r"\bxcodebuild\s+.*test-without-building\b",
    r"\bxcrun\s+simctl\s+launch\b",
    
    # Cross-Platform (React Native / Expo / Flutter)
    r"\b(npx\s+)?expo\s+(start|run:android|run:ios)\b",
    r"\b(npx\s+)?react-native\s+(start|run-android|run-ios)\b",
    r"\bflutter\s+(run|attach)\b",
    
    # Web & Server Frameworks (Angular, Vite, Webpack, etc.)
    r"\b(ng|npx\s+ng)\s+(serve|s)\b",
    r"\b(vite|npx\s+vite)\b",
]

# Extended non-blocking test runner rules
TEST_SANITY_RULES = [
    # Angular / Jasmine / Karma tests
    (r"\b(ng|npx\s+ng)\s+test\b", "--watch=false"),

    # Android / Gradle tests
    (r"\b(gradlew?|./gradlew)\s+test\b", "--info"),
    
    # iOS / Xcode tests
    (r"\bxcodebuild\s+test\b", "-disable-concurrent-destination-testing"),
    
    # Flutter tests
    (r"\bflutter\s+test\b", "--no-pub"),
    
    # React Native / Jest / Generic npm tests
    (r"\b(npm|yarn|pnpm|bun)\s+test\b", "-- --watchAll=false --watch=false"),
]


def intercept_and_sanitize_command(command: str) -> Tuple[bool, str, str]:
    """
    Validates and transforms commands across all software frameworks before execution.
    Returns: (is_blocked, transformed_command, error_reason)
    """
    cmd_str = command.strip()

    # Step 1: Check for long-running daemons or MCP background servers
    for pattern in BLOCKED_DAEMONS:
        if re.search(pattern, cmd_str, re.IGNORECASE):
            match = re.search(pattern, cmd_str, re.IGNORECASE)
            matched_text = match.group(0) if match else cmd_str
            
            if "mcp" in matched_text.lower():
                return True, cmd_str, (
                    f"Command '{matched_text}' launches a persistent Model Context Protocol (MCP) stdio server. "
                    f"MCP servers cannot be executed as one-shot shell tools. Fall back to standard file tools, search, or CLI commands."
                )
            
            return True, cmd_str, (
                f"Command '{matched_text}' launches an interactive daemon or long-running dev server. "
                f"Interactive processes are forbidden during agent execution turns. Use single-run bounded commands."
            )

    # Step 2: Auto-inject non-blocking flags into test commands
    for pattern, required_flag in TEST_SANITY_RULES:
        if re.search(pattern, cmd_str) and required_flag.split()[0] not in cmd_str:
            cmd_str = f"{cmd_str} {required_flag}"

    return False, cmd_str, ""


def is_high_risk(command: str) -> bool:
    """Checks whether a command string targets high-risk system binaries."""
    try:
        tokens = shlex.split(command)
        if not tokens:
            return False
        base_cmd = os.path.basename(tokens[0])
        return base_cmd in HIGHRISKCOMMANDS
    except ValueError:
        return True


def request_human_approval(command: str) -> bool:
    """Prompts human operator in terminal for approval on high-risk operations."""
    print(f"\n⚠️  [HITL GUARDRAIL INTERCEPT]: High-risk command detected!")
    print(f"👉 Command: '{command}'")
    response = input("Do you authorize execution? (y/N): ").strip().lower()
    return response == "y"


@track_latency
@audit_logger(log_file="async_telemetry.jsonl")
async def execute_async_subprocess(
    command: str,
    timeout: float = 30.0,
    bypass_hitl: bool = False
) -> Dict[str, Any]:
    """
    Executes a shell command asynchronously with HITL safety checks, command interception, and timeout guardrails.
    """
    # 1. Multi-Platform Interception & Sanitization
    is_blocked, sanitized_cmd, block_reason = intercept_and_sanitize_command(command)
    if is_blocked:
        print(f"🚫 [GUARDRAIL BLOCKED]: {block_reason}")
        return {
            "command": command,
            "stdout": "",
            "stderr": f"System Guardrail Error: {block_reason}",
            "returncode": 1,
            "status": "BLOCKED"
        }

    # 2. Human-in-the-Loop Guardrail
    if is_high_risk(sanitized_cmd) and not bypass_hitl:
        approved = request_human_approval(sanitized_cmd)
        if not approved:
            print("🚫 [HITL DENIED]: Command execution aborted by operator.")
            return {
                "command": sanitized_cmd,
                "stdout": "",
                "stderr": "Execution denied by human operator",
                "returncode": -1,
                "status": "DENIED"
            }

    # 3. Async Subprocess Execution
    print(f"⚡ [Executing Subprocess]: {sanitized_cmd}")
    try:
        process = await asyncio.create_subprocess_shell(
            sanitized_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        stdout_bytes, stderr_bytes = await asyncio.wait_for(
            process.communicate(), timeout=timeout
        )

        stdout = stdout_bytes.decode("utf-8").strip()
        stderr = stderr_bytes.decode("utf-8").strip()

        return {
            "command": sanitized_cmd,
            "stdout": stdout,
            "stderr": stderr,
            "returncode": process.returncode,
            "status": "SUCCESS" if process.returncode == 0 else "ERROR"
        }
    except asyncio.TimeoutError:
        print(f"⏰ [TIMEOUT EXCEEDED]: Process killed after {timeout} seconds.")
        try:
            process.kill()
            await process.wait()
        except ProcessLookupError:
            pass

        return {
            "command": sanitized_cmd,
            "stdout": "",
            "stderr": f"Command timed out after {timeout} seconds.",
            "returncode": -9,
            "status": "TIMEOUT"
        }


# Alias for tool execution parity across the ecosystem
run_shell_command = execute_async_subprocess

# Tool Schema Declaration for LLM Function Calling
SHELL_TOOLS_SCHEMA: List[Dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "run_shell_command",
            "description": "Executes a bash shell command asynchronously with HITL safety checks and timeout bounds.",
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "The exact shell command string to execute (e.g., 'git status', 'pytest', 'uv sync')."
                    },
                    "timeout": {
                        "type": "number",
                        "description": "Maximum execution time in seconds.",
                        "default": 30.0
                    }
                },
                "required": ["command"]
            }
        }
    }
]

ASYNC_TOOL_DISPATCHER = {
    "run_shell_command": run_shell_command
}