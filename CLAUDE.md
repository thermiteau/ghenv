# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

`ghenv` is a Python tool for managing GitHub environment variables and secrets across multiple deployment configurations. It provides bidirectional synchronization between local `.vars` and `.secs` files and GitHub environment settings.

## Common Development Commands

### Running Tests

```bash
# Run all tests
uv run pytest

# Run specific test file
uv run pytest tests/test_ghenv_lib.py

# Run with pytest directly (verbose mode)
uv run pytest tests/test_ghenv_lib.py -v

# Run specific test class
uv run pytest tests/test_ghenv_lib.py::TestSetupLogging -v

# Run specific test method
uv run pytest tests/test_ghenv_lib.py::TestReadVariableNames::test_read_variable_names_single_file -v

# Run with coverage
uv run pytest --cov=ghenv --cov-report=html
```

### Type Checking

```bash
# Run pyright type checker
uv run pyright

# Check specific file
uv run pyright src/ghenv/ghenv_lib.py
```

### Running the Scripts

```bash
# Set GitHub token (required for all operations)
export GH_API_SECRET="your_github_token"

# Using installed CLI commands (recommended)
uv run ghenv-check <owner> <repo> <env-name> <data-directory>
uv run ghenv-create <owner> <repo> <env-name> <data-directory>

# Using module syntax
uv run python -m ghenv.check <owner> <repo> <env-name> <data-directory>
uv run python -m ghenv.create <owner> <repo> <env-name> <data-directory>

# Using direct script execution
uv run python src/ghenv/check.py <owner> <repo> <env-name> <data-directory>
uv run python src/ghenv/create.py <owner> <repo> <env-name> <data-directory>

# Example
uv run ghenv-check myorg myrepo production data/
uv run ghenv-create myorg myrepo production data/
```

### Environment Variables

- `GH_API_SECRET`: GitHub token with `actions:write` permission (required)
- `LOG_LEVEL`: Set logging level (optional, defaults to INFO, options: DEBUG, INFO, WARNING, ERROR)

### Installing Dependencies

```bash
# Sync all dependencies (including test dependencies)
uv sync --all-extras

# Sync only production dependencies
uv sync

# Install the package in editable mode
uv pip install -e .

# Add a new dependency
uv add <package-name>

# Add a new test dependency
uv add --optional test <package-name>

# Update dependencies
uv lock --upgrade
```

## Architecture Overview

### Project Structure

```
ghenv/
├── src/ghenv/           # Main package source
│   ├── ghenv_lib.py     # Core library with shared utilities
│   ├── check.py         # Script to check environment synchronization
│   ├── create.py        # Script to create missing variables/secrets
│   └── __init__.py      # Package initialization
├── tests/               # Test suite
│   ├── test_ghenv_lib.py # Comprehensive unit tests
│   └── run_tests.py     # Test runner script
├── data/                # Optional directory for .vars and .secs files
├── pyproject.toml       # Project metadata and dependencies
├── main.py              # Entry point (minimal)
└── README.md            # Comprehensive documentation
```

### Core Components

**ghenv_lib.py** - Shared library containing:
- API interaction functions (GET/POST/PUT to GitHub API)
- Secret encryption using libsodium (PyNaCl)
- File parsing and deduplication logic
- Pagination support for large environments
- Logging setup with dual output (console + file)
- Environment validation

**check.py** - Bidirectional synchronization checker:
- Checks if local .vars/.secs files exist in GitHub
- Checks if GitHub variables/secrets exist in local files
- Reports missing and orphaned items
- Exit code 0 = synchronized, 1 = issues found

**create.py** - Variable/secret creator:
- Creates missing variables with value "NONE"
- Creates missing secrets with encrypted value "NONE"
- Uses GitHub's public key for secret encryption
- Idempotent - can be run multiple times safely

### Key Design Patterns

1. **Dual Import Pattern**: Scripts support both direct execution and module import:
   ```python
   try:
       from .ghenv_lib import ...  # Module import
   except ImportError:
       from ghenv_lib import ...   # Direct execution
   ```

2. **Deduplication**: Variable/secret names are stored in sets and sorted before processing

3. **Pagination**: All GitHub API list operations handle pagination with 100 items per page

4. **Logging**: Dual output to both console (stdout) and log files with timestamps

5. **Exit Codes**: Consistent use of sys.exit(1) for errors, sys.exit(0) or implicit 0 for success

## File Format Specifications

### .vars Files (Variables)
- One variable name per line
- Comments supported with `#` character
- Case-sensitive names
- Empty lines ignored
- Example: `deploy.yml.vars`

### .secs Files (Secrets)
- One secret name per line
- Comments supported with `#` character
- Case-sensitive names
- Empty lines ignored
- Example: `deploy.yml.secs`

### Naming Convention
Files should match GitHub workflow filenames:
- `.github/workflows/deploy.yml` → `data/deploy.yml.vars` and `data/deploy.yml.secs`

## GitHub API Integration

### Required Permissions
GitHub token must have `actions:write` permission for:
- Creating/updating environment variables
- Creating/updating environment secrets
- Reading environment configuration
- Accessing public keys for secret encryption

### API Endpoints Used
- `GET /repos/{owner}/{repo}/environments/{env}/variables` - List variables
- `GET /repos/{owner}/{repo}/environments/{env}/variables/{name}` - Check variable
- `POST /repos/{owner}/{repo}/environments/{env}/variables` - Create variable
- `GET /repos/{owner}/{repo}/environments/{env}/secrets` - List secrets
- `GET /repos/{owner}/{repo}/environments/{env}/secrets/{name}` - Check secret
- `PUT /repos/{owner}/{repo}/environments/{env}/secrets/{name}` - Create/update secret
- `GET /repos/{owner}/{repo}/environments/{env}/secrets/public-key` - Get encryption key

### API Version
All requests use API version `2022-11-28` via `X-GitHub-Api-Version` header

## Testing Strategy

### Test Structure
- Comprehensive unit tests in `test_ghenv_lib.py`
- Tests organized by function in classes (e.g., `TestSetupLogging`, `TestReadVariableNames`)
- Integration tests included in `TestIntegration` class

### Testing Tools
- **pytest**: Main test framework
- **pytest-mock**: For mocking dependencies
- **requests-mock**: For mocking HTTP requests to GitHub API
- **unittest.mock**: For patching file operations and environment variables

### Test Coverage Areas
- File parsing and deduplication
- GitHub API interactions (success and error cases)
- Secret encryption/decryption
- Pagination handling
- Environment validation
- Logging configuration
- Error handling and exit codes

## Development Guidelines

### Python Version
Requires Python 3.10+ (specified in pyproject.toml)

### Dependencies
- `pynacl>=1.6.0`: Libsodium bindings for secret encryption
- `requests>=2.32.4`: HTTP library for GitHub API calls
- Test dependencies: `pytest`, `pytest-mock`, `requests-mock`

### Code Style
- Comprehensive docstrings for all functions (Google style)
- Type hints in function signatures
- Detailed inline comments explaining complex logic
- Consistent error handling with logging before exit

### Logging Best Practices
- Always create logger using `setup_logging(log_file, logger_name)`
- Log files stored in `src/ghenv/logs/` directory
- Use appropriate log levels (INFO for normal flow, ERROR for failures)
- Include context in error messages (variable names, status codes, etc.)

### Error Handling
- Always log errors before calling `sys.exit(1)`
- Use status code checks (200, 201 for success)
- Provide actionable error messages with details (status codes, response text)

## Integration Patterns

### Makefile Integration
Common pattern for integrating into project Makefiles:
```makefile
envcheck:
	@uv run ghenv-check ${OWNER} ${REPO} ${GH_ENV_NAME} ghenv/data

envcreate:
	@uv run ghenv-create ${OWNER} ${REPO} ${GH_ENV_NAME} ghenv/data

# Alternative using module syntax
envcheck-alt:
	@uv run python -m ghenv.check ${OWNER} ${REPO} ${GH_ENV_NAME} ghenv/data
```

### CI/CD Integration
Run `check.py` in CI/CD pipelines to fail builds early if environment configuration is incomplete:
```yaml
- name: Install uv
  uses: astral-sh/setup-uv@v1

- name: Check GitHub Environment
  env:
    GH_API_SECRET: ${{ secrets.GITHUB_TOKEN }}
  run: uv run ghenv-check myorg myrepo production ghenv/data
```

## Security Considerations

1. **Never commit actual secret values** - only commit secret names in .secs files
2. **GitHub token security** - store in environment variable, never in code
3. **Secret encryption** - all secrets encrypted with GitHub's public key before transmission
4. **Placeholder values** - created variables/secrets use "NONE" as placeholder
5. **Log file sensitivity** - log files may contain variable/secret names but never values
