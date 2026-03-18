---
title: Unit Testing -- Project Implementation
topic: unit-testing
last-verified: 2026-03-18
---

## Stack

pytest 7.0+ as the test framework, with pytest-mock 3.10+ for mocking, requests-mock 1.10+ for HTTP stubbing, and pytest-cov 4.0+ for coverage reporting. All declared as optional test dependencies in pyproject.toml. Tests run via `uv run pytest`.

## Configuration

No dedicated pytest configuration file exists. Test dependencies are declared under `[project.optional-dependencies] test` in `pyproject.toml` and installed via `uv sync --all-extras`. The test file imports the package by inserting `src/` into `sys.path` at the top of the test module. Coverage is collected with `uv run pytest --cov=ghenv --cov-report=html`.

## Patterns

- **Class-based grouping**: Tests are organised into classes by function under test (e.g., `TestSetupLogging`, `TestReadVariableNames`, `TestPutVariable`). Each class contains multiple test methods.
- **Arrange-Act-Assert**: All tests follow this structure. Setup uses pytest fixtures (`tmp_path`, `capsys`, `requests_mock`) and `unittest.mock` (Mock, mock_open, patch).
- **HTTP mocking via requests-mock**: All GitHub API calls are stubbed using the `requests_mock` fixture. Tests register URL patterns with expected status codes and response bodies.
- **File system mocking**: File reading is mocked with `mock_open` for unit isolation. Integration tests use `tmp_path` to create real temporary files.
- **Environment variable mocking**: `patch.dict(os.environ, ...)` is used to test token validation and log level configuration.
- **SystemExit assertions**: Error paths that call `sys.exit(1)` are tested with `pytest.raises(SystemExit)`.
- **Integration test class**: `TestIntegration` combines multiple library functions in a single workflow test with full API mocking.
- **No conftest.py**: All fixtures come from pytest built-ins or plugin fixtures. No shared custom fixtures.

## File Locations

- `tests/test_ghenv_lib.py` -- all unit and integration tests (single test file)
- `tests/run_tests.py` -- test runner script (alternative to `uv run pytest`)
- `tests/test_data/` -- fixture files (var_file_a.vars, var_file_b.vars, cdk-output.json)
- `pyproject.toml` -- test dependency declarations under `[project.optional-dependencies]`
