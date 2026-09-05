import pytest
from unittest.mock import patch
from agent_async_runner.runner import (
    is_high_risk,
    intercept_and_sanitize_command,
    execute_async_subprocess,
)


def test_is_high_risk_detection():
    assert is_high_risk("rm -rf /tmp/test") is True
    assert is_high_risk("sudo apt update") is True
    assert is_high_risk("ls -la") is False


def test_intercept_and_sanitize_command_daemons():
    # Angular / Web Daemons
    blocked, _, err = intercept_and_sanitize_command("ng mcp")
    assert blocked is True
    assert "interactive daemon" in err

    blocked, _, _ = intercept_and_sanitize_command("npm run dev")
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