import pytest
from unittest.mock import patch, AsyncMock
from agent_async_runner.runner import (
    is_high_risk,
    intercept_and_sanitize_command,
    execute_async_subprocess,
)
from agent_async_runner.git_utils import get_git_status_changes


def test_is_high_risk_detection():
    assert is_high_risk("rm -rf /tmp/test") is True
    assert is_high_risk("sudo apt update") is True
    assert is_high_risk("ls -la") is False


def test_intercept_and_sanitize_command_daemons():
    # Blanket MCP Blocking Assertions
    blocked, _, err = intercept_and_sanitize_command("ng mcp")
    assert blocked is True
    assert "strictly disabled" in err or "Protocol server execution" in err

    blocked, _, err = intercept_and_sanitize_command("npx mcp-server-git")
    assert blocked is True
    assert "strictly disabled" in err or "Protocol server execution" in err

    blocked, _, err = intercept_and_sanitize_command("npx ng mcp --help")
    assert blocked is True
    assert "strictly disabled" in err or "Protocol server execution" in err

    # Web & Server Daemons
    blocked, _, err = intercept_and_sanitize_command("ng serve")
    assert blocked is True
    assert "interactive daemon" in err

    blocked, _, _ = intercept_and_sanitize_command("vite")
    assert blocked is True

    # Mobile Daemons (Android / iOS / Expo / Flutter)
    blocked, _, _ = intercept_and_sanitize_command("flutter run")
    assert blocked is True

    blocked, _, _ = intercept_and_sanitize_command("npx expo start")
    assert blocked is True

    blocked, _, _ = intercept_and_sanitize_command("./gradlew app:run")
    assert blocked is True


def test_intercept_and_sanitize_command_test_flags():
    # Auto-injects --watch=false into Angular test
    blocked, sanitized, _ = intercept_and_sanitize_command("ng test")
    assert blocked is False
    assert "--watch=false" in sanitized

    # Auto-injects --watch=false into npm test
    blocked, sanitized, _ = intercept_and_sanitize_command("npm test")
    assert blocked is False
    assert "--watch=false" in sanitized

    # Retains existing non-blocking flags
    blocked, sanitized, _ = intercept_and_sanitize_command("ng test --watch=false")
    assert blocked is False
    assert sanitized == "ng test --watch=false"


@pytest.mark.asyncio
async def test_execute_async_subprocess_blocked():
    result = await execute_async_subprocess("ng serve")
    assert result["status"] == "BLOCKED"
    assert result["returncode"] == 1
    assert "System Guardrail Error" in result["stderr"]


@pytest.mark.asyncio
async def test_execute_async_subprocess_mcp_blocked():
    result = await execute_async_subprocess("ng mcp")
    assert result["status"] == "BLOCKED"
    assert result["returncode"] == 1
    assert "Protocol server execution" in result["stderr"] or "strictly disabled" in result["stderr"]


@pytest.mark.asyncio
async def test_execute_async_subprocess_success():
    result = await execute_async_subprocess("echo 'Async Runner Test'")
    assert result["status"] == "SUCCESS"
    assert result["stdout"] == "Async Runner Test"


@pytest.mark.asyncio
async def test_execute_async_subprocess_timeout():
    result = await execute_async_subprocess("sleep 2", timeout=0.2)
    assert result["status"] == "TIMEOUT"
    assert result["returncode"] == -9


@pytest.mark.asyncio
@patch("agent_async_runner.runner.request_human_approval", return_value=False)
async def test_execute_async_subprocess_hitl_denied(mock_hitl):
    result = await execute_async_subprocess("rm -rf /dummy/path")
    assert result["status"] == "DENIED"
    assert result["returncode"] == -1
    mock_hitl.assert_called_once()


# =====================================================================
# Tests for git_utils.py
# =====================================================================

@pytest.mark.asyncio
@patch("agent_async_runner.git_utils.execute_async_subprocess", new_callable=AsyncMock)
async def test_get_git_status_changes_non_git_repo(mock_exec):
    """Verify returns (False, empty, empty) when git returns non-zero status."""
    mock_exec.return_value = {
        "returncode": 128,
        "stdout": "",
        "stderr": "fatal: not a git repository",
        "status": "ERROR"
    }

    is_git, update_files, delete_files = await get_git_status_changes("/fake/dir")

    assert is_git is False
    assert update_files == set()
    assert delete_files == set()


@pytest.mark.asyncio
@patch("agent_async_runner.git_utils.os.path.isfile", return_value=True)
@patch("agent_async_runner.git_utils.execute_async_subprocess", new_callable=AsyncMock)
async def test_get_git_status_changes_parses_updates_and_deletes(mock_exec, mock_isfile):
    """Verify correctly categorizes updated, untracked, and deleted files from git status porcelain."""
    mock_exec.side_effect = [
        {"returncode": 0, "stdout": "true", "stderr": "", "status": "SUCCESS"},
        {
            "returncode": 0,
            "stdout": " M src/app.ts\n?? src/new_component.ts\n D src/old_component.ts\n M \"src/file with spaces.ts\"",
            "stderr": "",
            "status": "SUCCESS"
        }
    ]

    is_git, update_files, delete_files = await get_git_status_changes("/fake/dir")

    assert is_git is True
    assert "src/app.ts" in update_files
    assert "src/new_component.ts" in update_files
    assert "src/file with spaces.ts" in update_files
    assert "src/old_component.ts" in delete_files