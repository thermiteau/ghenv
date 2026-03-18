---
title: Logging -- Project Implementation
topic: logging
last-verified: 2026-03-18
---

## Stack

Python standard library `logging` module. No third-party logging libraries. Configured via a custom `setup_logging` function in `ghenv_lib.py`.

## Configuration

Log level is controlled by the `LOG_LEVEL` environment variable, defaulting to `INFO` and forced to uppercase. Each CLI command creates its own named logger at module import time by calling `setup_logging(log_file, logger_name)`. Log files are written to `src/ghenv/logs/` (created automatically via `os.makedirs` with `exist_ok=True`). The log format is `%(asctime)s | %(name)s | %(levelname)s | %(message)s` with datefmt `%Y-%m-%d %H:%M:%S`.

## Patterns

- **Dual output**: Every logger has two handlers -- a `FileHandler` writing to the logs directory and a `StreamHandler` writing to `sys.stdout`.
- **One logger per CLI command**: `check.py` creates `setup_logging("check.log", "check")`, `create.py` uses `"create.log"/"create"`, `update.py` uses `"update.log"/"update"`, `delete.py` uses `"delete.log"/"delete"`.
- **Module-level initialisation**: Loggers are created at module import time (top of each script, outside `main()`). This means importing the module triggers log directory and file creation.
- **Logger passed as parameter**: All `ghenv_lib` functions that need logging accept a `Logger` instance as a parameter rather than creating their own.
- **Error-then-exit pattern**: On fatal errors, functions log the error with full context (status code, response text, URL) then call `sys.exit(1)`.
- **Uses `logging.basicConfig`**: Configuration is applied globally via `basicConfig`, which means only the first call takes effect if multiple modules are imported.

## File Locations

- `src/ghenv/ghenv_lib.py` -- contains `setup_logging()` function definition
- `src/ghenv/check.py` -- logger initialisation at line 56
- `src/ghenv/create.py` -- logger initialisation at line 60
- `src/ghenv/update.py` -- logger initialisation at line 77
- `src/ghenv/delete.py` -- logger initialisation at line 61
- `src/ghenv/logs/` -- runtime log output directory (gitignored)
