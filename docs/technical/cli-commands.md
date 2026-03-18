---
title: CLI Commands and File Formats
scope: component
relates-to: [architecture-overview.md, github-api-integration.md]
last-verified: 2026-03-18
---

## Overview

ghenv exposes four CLI commands registered as console_scripts entry points in pyproject.toml. Each command maps to a module with a `main()` function that parses arguments, validates the environment, and executes its operation.

## CLI Entry Points

| Command | Module | Purpose |
|---|---|---|
| `ghenv-check` | `ghenv.check:main` | Compare local files against GitHub environment; report drift |
| `ghenv-create` | `ghenv.create:main` | Create missing variables/secrets with placeholder values |
| `ghenv-update` | `ghenv.update:main` | Update existing variables/secrets with values from a file |
| `ghenv-delete` | `ghenv.delete:main` | Remove orphaned variables/secrets not in local files |

## Command Signatures

### ghenv-check

```
ghenv-check <owner> <repo> <env_name> <vars_dir>
```

- Reads `.vars` and `.secs` files from `vars_dir`
- Fetches all variables and secrets from GitHub (paginated)
- Reports items missing from GitHub (local-only) and orphaned in GitHub (remote-only)
- Exit code 0 = synchronised, 1 = drift detected or error

### ghenv-create

```
ghenv-create <owner> <repo> <env_name> <vars_dir>
```

- Reads `.vars` and `.secs` files from `vars_dir`
- Pre-fetches existing items to skip already-present ones
- Creates missing variables (POST, value "NONE") and secrets (PUT, encrypted "NONE")
- Idempotent -- safe to run repeatedly

### ghenv-update

```
ghenv-update <owner> <repo> <env_name> <file_path>
```

- Accepts a single `.txt` or `.json` file (not a directory)
- For each name=value pair: checks if name exists as a variable or secret in GitHub
- Updates variables via PATCH, secrets via PUT with encryption
- Skips names not found in the GitHub environment (logs warning)

### ghenv-delete

```
ghenv-delete <owner> <repo> <env_name> <vars_dir> [--dry-run]
```

- Reads `.vars` and `.secs` files from `vars_dir`
- Identifies orphaned items (in GitHub but not in local files)
- Deletes orphaned items, or previews them in `--dry-run` mode
- If no `.vars`/`.secs` files exist but GitHub has items, logs a warning and skips (safety guard)

## File Formats

### .vars and .secs Files (Name Lists)

Used by check, create, and delete commands.

- One name per line
- Lines starting with `#` are comments
- Inline comments supported: `NAME # comment` extracts `NAME`
- Empty and whitespace-only lines are ignored
- Names are deduplicated across all files using a set, then sorted
- Naming convention: match workflow filenames (e.g., `deploy.yml.vars`)

### .txt Files (Key=Value Pairs)

Used by the update command.

- Format: `NAME=VALUE` (one per line)
- Split on first `=` only (values may contain `=`)
- Comments with `#`, empty lines ignored
- Both name and value are stripped of whitespace
- Pairs with empty name or value after stripping are skipped

### .json Files (AWS CDK Output Format)

Used by the update command.

- Expected structure: `{ "stack-name": { "camelCaseKey": "value", ... } }`
- Top-level keys are iterated; nested objects have their keys transformed
- Key transformation: `camelCase` to `UPPER_SNAKE_CASE` via regex (`re.sub(r'(?<!^)(?=[A-Z])', '_', s).upper()`)
- All values are cast to string

## Shared Infrastructure

### Logging

- `setup_logging(log_file, logger_name)` creates a logger with dual handlers:
  - FileHandler writing to `src/ghenv/logs/{log_file}`
  - StreamHandler writing to stdout
- Format: `%(asctime)s | %(name)s | %(levelname)s | %(message)s`
- Log level controlled by `LOG_LEVEL` environment variable (default: INFO), forced to uppercase
- Each CLI script creates its own logger at module level (e.g., `setup_logging("check.log", "check")`)

### Environment Validation

`validate_environment(owner, repo, env_name, vars_dir, logger)` performs:

1. Check `GH_API_SECRET` environment variable is set
2. Validate `vars_dir` exists as a directory
3. Return `(token, Path(vars_dir))` or `sys.exit(1)`

Used by check, create, and delete. The update command performs its own inline validation (checks token and file existence separately).

## Design Decisions

- **Module-level logger initialisation**: Each CLI script calls `setup_logging()` at import time. This means importing the module triggers log file creation. Acceptable for CLI tools but would be problematic for library use.
- **argparse for CLI**: Standard library argument parsing. No third-party CLI framework (e.g., click, typer) -- keeps dependencies minimal.
- **Separate scripts per operation**: Each operation is a standalone module rather than subcommands of a single CLI. This simplifies individual invocation from Makefiles and CI pipelines.
