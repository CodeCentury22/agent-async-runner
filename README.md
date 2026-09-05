# Agent Async Runner ⚡🛡️

Async subprocess execution engine with Human-in-the-Loop (HITL) approval guardrails and execution timeouts for local AI agents.

## Features

* **Async Subprocess Execution**: Non-blocking `asyncio` subprocess execution for shell commands.
* **HITL Guardrails**: Intercepts high-risk shell commands (e.g., `rm`, `sudo`, `chmod`) and prompts the operator for terminal authorization before running.
* **Timeout Protection**: Automatically terminates hanging processes after a configurable timeout limit.
* **Telemetry & Auditing**: Integrated with `@track_latency` and `@audit_logger` for performance and execution tracking.

## Installation

Add `agent-async-runner` to your project using `uv`:

```bash
uv add git+[https://github.com/CodeCentury22/agent-async-runner.git@v0.4.3](https://github.com/CodeCentury22/agent-async-runner.git@v0.4.3)