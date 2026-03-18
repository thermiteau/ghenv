---
title: Linting -- Project Implementation
topic: linting
last-verified: 2026-03-18
status: implemented
---

## Stack

- **Linter**: Ruff (`ruff check`)
- **Formatter**: Ruff (`ruff format`)
- **Type checker**: Pyright (`pyright`) — `basic` mode, `src/` only (tests excluded to avoid false positives from heavy mocking)
- **Ruff version**: `>=0.8.0` (installed as a uv dev dependency)
- **Pyright version**: `>=1.1.390` (installed as a uv dev dependency)
- **Rule sets**: `E` (pycodestyle errors), `W` (pycodestyle warnings), `F` (pyflakes), `I` (isort), `UP` (pyupgrade), `B` (flake8-bugbear), `SIM` (flake8-simplify)

## Configuration

All configuration lives in `pyproject.toml` under `[tool.ruff]`:

```toml
[tool.ruff]
target-version = "py310"
src = ["src"]
line-length = 99

[tool.ruff.lint]
select = ["E", "W", "F", "I", "UP", "B", "SIM"]

[tool.ruff.lint.isort]
known-first-party = ["ghenv"]
```

No separate config files (`.ruff.toml`, `setup.cfg`, etc.) are used.

## Commands

```bash
# Lint check
uv run ruff check .

# Lint with auto-fix
uv run ruff check --fix .

# Format check (dry run)
uv run ruff format --check .

# Format (apply changes)
uv run ruff format .

# Type check
uv run pyright
```

## Patterns

- **Line length**: 99 characters. Long f-strings in log messages are split using implicit string concatenation across lines.
- **Imports**: Sorted by isort rules (`I`). Standard library, third-party, and first-party (`ghenv`) groups are separated automatically.
- **Type annotations**: Modern Python 3.10+ syntax (`list`, `dict`, `tuple`) used instead of `typing.List`, `typing.Dict`, `typing.Tuple` (enforced by `UP` rules).
- **Unused variables**: Loop variables that are intentionally unused are prefixed with `_` (e.g., `_top_level_key`).

## Configuration — Pyright

All configuration lives in `pyproject.toml` under `[tool.pyright]`:

```toml
[tool.pyright]
pythonVersion = "3.10"
typeCheckingMode = "basic"
include = ["src"]
```

- `basic` mode catches real type bugs (e.g., invariant `list` mismatches) without noisy strictness.
- Tests are excluded — heavy mocking causes false positives.

## File Locations

| Concern | Location |
|---|---|
| Ruff configuration | `pyproject.toml` (`[tool.ruff]`, `[tool.ruff.lint]`, `[tool.ruff.lint.isort]`) |
| Pyright configuration | `pyproject.toml` (`[tool.pyright]`) |
| Dev dependencies | `pyproject.toml` (`[tool.uv] dev-dependencies`) |
