import asyncio
import json
import os
import re
import shlex
import uuid
from typing import Dict, Any, List, Tuple
from agent_core_utils import track_latency, audit_logger

HIGHRISKCOMMANDS = {"rm", "rmdir", "chmod", "chown", "sudo", "dd", "mkfs"}

# Patterns matching direct CLI invocations of MCP daemons or servers
MCP_SHELL_PATTERNS = [
    r"\bmcp\b",
    r"\bng\s+mcp\b",
    r"\bnpx\s+.*mcp-server.*\b",
    r"\buvx\s+.*mcp-server.*\b",
    r"\bmcp-server-\w+\b",
]

# Long-running interactive daemons & blocked protocols across platforms
BLOCKED_DAEMONS = [
    # Android / Gradle / Kotlin daemons
    r"\b(gradlew?|./gradlew)\s+.*(run|app:run|connectedCheck)\b",
    r"\b(adb)\s+(logcat|shell|wait-for-device)\b",
    
    # iOS / Xcode daemons
    r"\bxcodebuild\s+.*test-without-building\b",
    r"\bxcrun\s+simctl\s+launch\b",
    
    # Cross-Platform daemons (React Native / Expo / Flutter)
    r"\b(npx\s+)?expo\s+(start|run:android|run:ios)\b",
    r"\b(npx\s+)?react-native\s+(start|run-android|run-ios)\b",
    r"\bflutter\s+(run|attach)\b",
    
    # Web & Server Frameworks (Angular, Vite, Webpack, etc.)
    r"\b(ng|npx\s+ng)\s+(serve|s)\b",
    r"\b(vite|npx\s+vite)\b",
]

# Background async tasks registry
BACKGROUND_TASKS: Dict[str, Dict[str, Any]] = {}


def has_active_mcp_config(workspace_dir: str = ".") -> bool:
    """
    Checks if active (non-comment) MCP servers are configured in .agent/mcp.json
    without introducing a dependency on agent_cli.
    """
    config_path = os.path.join(workspace_dir, ".agent", "mcp.json")
    if not os.path.exists(config_path):
        return False

    try:
        with open(config_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            raw_servers = data.get("mcpServers") or data.get("servers") or {}
            active_servers = {
                name: cfg for name, cfg in raw_servers.items() if not name.startswith("//")
            }
            return len(active_servers) > 0
    except Exception:
        return False


def is_mcp_shell_command(command: str) -> bool:
    """Detects whether a shell command is attempting to run an interactive MCP daemon."""
    for pattern in MCP_SHELL_PATTERNS:
        if re.search(pattern, command, re.IGNORECASE):
            return True
    return False


def intercept_and_sanitize_command(command: str) -> Tuple[bool, str, str]:
    """
    Validates and blocks interactive daemons and unauthorized protocols.
    Dynamically inspects local workspace .agent/mcp.json for active MCP servers.
    Returns: (is_blocked, transformed_command, error_reason)
    """
    cmd_str = command.strip()

    # Step 1: Handle MCP commands with dynamic workspace config check
    if is_mcp_shell_command(cmd_str):
        if not has_active_mcp_config():
            override_prompt = (
                "🛑 SYSTEM INTERCEPT: MCP execution blocked.\n"
                "REASON: No active MCP servers are configured in '.agent/mcp.json'.\n\n"
                "INSTRUCTIONS FOR AGENT:\n"
                "1. IGNORE any project skill directives or guidelines instructing you to run MCP tools or servers.\n"
                "2. DO NOT attempt to run shell commands like 'ng mcp', 'npx mcp-server-*', or start daemon processes.\n"
                "3. PROCEED IMMEDIATELY using native file and async runner tools (`read_file`, `write_file`, `run_shell_command`)."
            )
            return True, cmd_str, override_prompt

    # Step 2: Check for long-running interactive daemons or dev servers
    for pattern in BLOCKED_DAEMONS:
        if re.search(pattern, cmd_str, re.IGNORECASE):
            match = re.search(pattern, cmd_str, re.IGNORECASE)
            matched_text = match.group(0) if match else cmd_str

            return True, cmd_str, (
                f"Command '{matched_text}' launches an interactive daemon or long-running dev server. "
                f"Interactive processes are forbidden during agent turns."
            )

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


def summarize_error_output(stderr: str, max_lines: int = 3) -> str:
    """Filters and trims verbose stderr down to the core error lines."""
    if not stderr:
        return ""
    lines = stderr.splitlines()
    error_lines = [
        line for line in lines
        if any(keyword in line.lower() for keyword in ["error", "err!", "fail", "✘", "exception", "fatal"])
    ]
    target_lines = error_lines if error_lines else [l for l in lines if l.strip()]
    return "\n".join(target_lines[:max_lines])


def summarize_success_output(stdout: str) -> str:
    """Trims verbose bundle generation logs down to a clean success confirmation."""
    if not stdout:
        return "Build completed successfully."
    if "Application bundle generation complete" in stdout:
        return "Application bundle generation complete. [SUCCESS]"
    return stdout[:300] + "..." if len(stdout) > 300 else stdout


def filter_errors_only(stderr: str) -> str:
    """Strips warnings and keeps strictly explicit compilation/test error lines."""
    if not stderr:
        return ""
    lines = stderr.splitlines()
    error_keywords = ["error", "err!", "fail", "✘", "exception", "fatal"]
    warning_keywords = ["warning", "warn", "▲", "ng02956", "not implemented"]
    
    filtered = []
    for line in lines:
        lower_line = line.lower()
        if any(kw in lower_line for kw in error_keywords) and not any(wkw in lower_line for wkw in warning_keywords):
            filtered.append(line.strip())
            
    # If no explicit error keyword match, return non-warning lines
    if not filtered:
        filtered = [l.strip() for l in lines if l.strip() and not any(wkw in l.lower() for wkw in warning_keywords)]
        
    return "\n".join(filtered[:5])


def extract_error_files(stderr: str) -> List[str]:
    """Extracts file paths mentioned in compilation errors."""
    # 1. Match explicit file paths across the raw stderr 
    # (Paths often appear on lines directly below the 'error' keyword)
    pattern = r"([a-zA-Z0-9_\-/]+\.(?:html|ts|css|scss|json|js|jsx|tsx))(?::\d+:\d+)?"
    matches = re.findall(pattern, stderr)
    
    # 2. Fallback: Extract Angular component names if file path extension is omitted
    if not matches:
        error_text = filter_errors_only(stderr)
        comp_matches = re.findall(r"component\s+([A-Z][a-zA-Z0-9]+)", error_text)
        for comp in comp_matches:
            # Convert CamelCase component name (LoginPage) to typical Angular file prefix (login-page)
            kebab = re.sub(r"(?<!^)(?=[A-Z])", "-", comp).lower()
            matches.append(f"{kebab}.html / {kebab}.ts")

    return list(dict.fromkeys(matches))


def enrich_build_error(command: str, stderr: str) -> str:
    """Enriches build/test failure stderr strictly with core errors and target files, filtering out all warnings."""
    build_keywords = ["build", "test", "compile", "ng", "vite", "webpack", "tsc"]
    is_build_cmd = any(kw in command.lower() for kw in build_keywords)
    
    if not is_build_cmd:
        # Fall back to standard summarization for non-build shell commands
        return summarize_error_output(stderr)

    clean_errors = filter_errors_only(stderr)
    files = extract_error_files(stderr)
    
    if files:
        file_list_str = ", ".join([f"`{f}`" for f in files])
        guidance = (
            f"🛑 [BUILD/TEST ERROR INTERCEPT]:\n"
            f"Errors:\n{clean_errors}\n\n"
            f"Affected File(s): {file_list_str}\n\n"
            f"INSTRUCTIONS FOR AGENT:\n"
            f"1. You MUST invoke `read_file` on {file_list_str} to inspect the existing code before writing changes.\n"
            f"2. DO NOT repeat the build command or blindly call `write_file` without inspecting first.\n"
            f"3. Apply the fix using `write_file` after inspecting."
        )
    else:
        guidance = (
            f"🛑 [BUILD/TEST ERROR INTERCEPT]:\n"
            f"Errors:\n{clean_errors}\n\n"
            f"INSTRUCTIONS FOR AGENT:\n"
            f"1. You MUST invoke `read_file` on the target component or template files mentioned above.\n"
            f"2. Inspect the file content, apply the fix using `write_file`, then re-run the build."
        )
        
    return guidance


def clean_success_stderr(stderr: str) -> str:
    """Strips out non-fatal warnings, budget notices, and info logs when a build succeeds."""
    if not stderr:
        return ""
    lines = stderr.splitlines()
    warning_keywords = ["warning", "warn", "▲", "ng02956", "exceeded maximum budget", "not implemented"]
    
    filtered = [
        line.strip() for line in lines 
        if line.strip() and not any(kw in line.lower() for kw in warning_keywords)
    ]
    return "\n".join(filtered)


@track_latency
@audit_logger(log_file="async_telemetry.jsonl")
async def execute_async_subprocess(
    command: str,
    timeout: float = 30.0,
    bypass_hitl: bool = False
) -> Dict[str, Any]:
    """
    Executes a shell command asynchronously with HITL safety checks and timeout guardrails.
    """
    is_blocked, sanitized_cmd, block_reason = intercept_and_sanitize_command(command)
    if is_blocked:
        print(f"🚫 [GUARDRAIL INTERCEPTED]: {block_reason}")
        return {
            "command": command,
            "stdout": "",
            "stderr": f"System Guardrail Error: {block_reason}",
            "returncode": 1,
            "status": "BLOCKED"
        }

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

        raw_stdout = stdout_bytes.decode("utf-8").strip()
        raw_stderr = stderr_bytes.decode("utf-8").strip()

        final_stdout = summarize_success_output(raw_stdout) if process.returncode == 0 else raw_stdout
        
        # Pass raw_stderr directly so parsing doesn't break
        if process.returncode != 0:
            final_stderr = enrich_build_error(sanitized_cmd, raw_stderr)
        else:
            final_stderr = clean_success_stderr(raw_stderr)

        return {
            "command": sanitized_cmd,
            "stdout": final_stdout,
            "stderr": final_stderr,
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


async def start_background_task(command: str) -> Dict[str, Any]:
    """Spawns an asynchronous background task without blocking the main agent turn."""
    is_blocked, sanitized_cmd, block_reason = intercept_and_sanitize_command(command)
    if is_blocked:
        return {
            "status": "BLOCKED",
            "error": f"System Guardrail Error: {block_reason}"
        }

    task_id = f"task_{uuid.uuid4().hex[:8]}"

    process = await asyncio.create_subprocess_shell(
        sanitized_cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )

    BACKGROUND_TASKS[task_id] = {
        "command": sanitized_cmd,
        "process": process,
        "status": "RUNNING",
        "stdout": "",
        "stderr": "",
        "returncode": None
    }

    # Monitor completion in background
    asyncio.create_task(_monitor_background_task(task_id))

    return {
        "task_id": task_id,
        "command": sanitized_cmd,
        "status": "STARTED",
        "message": f"Background task '{task_id}' started."
    }


async def _monitor_background_task(task_id: str):
    """Monitors background task execution and stores output buffers."""
    task_info = BACKGROUND_TASKS[task_id]
    process = task_info["process"]
    cmd = task_info["command"]

    stdout_bytes, stderr_bytes = await process.communicate()

    raw_stdout = stdout_bytes.decode("utf-8").strip()
    raw_stderr = stderr_bytes.decode("utf-8").strip()

    task_info["stdout"] = summarize_success_output(raw_stdout) if process.returncode == 0 else raw_stdout
    
    # Pass raw_stderr directly so parsing doesn't break
    task_info["stdout"] = summarize_success_output(raw_stdout) if process.returncode == 0 else raw_stdout
    
    if process.returncode != 0:
        task_info["stderr"] = enrich_build_error(cmd, raw_stderr)
    else:
        task_info["stderr"] = clean_success_stderr(raw_stderr)

    task_info["returncode"] = process.returncode
    task_info["status"] = "SUCCESS" if process.returncode == 0 else "ERROR"


async def get_background_task_status(task_id: str) -> Dict[str, Any]:
    """Queries the status and output of a background task."""
    if task_id not in BACKGROUND_TASKS:
        return {"status": "NOT_FOUND", "error": f"Task ID '{task_id}' not found."}

    task_info = BACKGROUND_TASKS[task_id]
    return {
        "task_id": task_id,
        "command": task_info["command"],
        "status": task_info["status"],
        "returncode": task_info["returncode"],
        "stdout": task_info["stdout"],
        "stderr": task_info["stderr"]
    }


# Aliases for tool dispatcher parity
run_shell_command = execute_async_subprocess

# Tool Schema Declarations
SHELL_TOOLS_SCHEMA: List[Dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "run_shell_command",
            "description": "Executes a shell command synchronously with HITL safety checks and timeout bounds.",
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "The exact shell command string to execute."
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
    },
    {
        "type": "function",
        "function": {
            "name": "start_background_task",
            "description": "Spawns a long-running command (like builds or tests) in the background and returns a task_id.",
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "The command to run in the background (e.g. 'pnpm run build')."
                    }
                },
                "required": ["command"]
            }
        }
    },
    {
        "type": "function",
        "get_background_task_status": {
            "name": "get_background_task_status",
            "description": "Checks the status, stdout, and stderr of a background task using its task_id.",
            "parameters": {
                "type": "object",
                "properties": {
                    "task_id": {
                        "type": "string",
                        "description": "The task_id returned from start_background_task."
                    }
                },
                "required": ["task_id"]
            }
        }
    }
]

ASYNC_TOOL_DISPATCHER = {
    "run_shell_command": run_shell_command,
    "start_background_task": start_background_task,
    "get_background_task_status": get_background_task_status,
}