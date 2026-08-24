import asyncio
import os
import shlex
from typing import Dict, Any, List
from agent_core_utils import track_latency, audit_logger

HIGHRISKCOMMANDS = {"rm", "rmdir", "chmod", "chown", "sudo", "dd", "mkfs"}

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
    Executes a shell command asynchronously with HITL safety checks and timeout guardrails.
    """
    # 1. Human-in-the-Loop Guardrail
    if is_high_risk(command) and not bypass_hitl:
        approved = request_human_approval(command)
        if not approved:
            print("🚫 [HITL DENIED]: Command execution aborted by operator.")
            return {
                "command": command,
                "stdout": "",
                "stderr": "Execution denied by human operator",
                "returncode": -1,
                "status": "DENIED"
            }

    # 2. Async subprocess Execution
    print(f"⚡ [Executing Subprocess]: {command}")
    try:
        process = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        stdout_bytes, stderr_bytes = await asyncio.wait_for(
            process.communicate(), timeout=timeout
        )

        stdout = stdout_bytes.decode("utf-8").strip()
        stderr = stderr_bytes.decode("utf-8").strip()

        return {
            "command": command,
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
            "command": command,
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