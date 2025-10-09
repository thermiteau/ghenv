# GitHub Environment Variable Management

This directory contains Python scripts for managing GitHub environment variables across multiple deployment configurations.

## File Structure

```
ghenv/
├── README.md              # This documentation
├── CLAUDE.md              # Development guide for Claude Code
├── pyproject.toml         # Project configuration and dependencies
├── uv.lock                # Locked dependencies
├── .python-version        # Python version specification
├── src/ghenv/             # Main package source
│   ├── __init__.py        # Package initialization
│   ├── check.py           # Check environment for secrets/variables
│   ├── create.py          # Create missing secrets/variables
│   ├── ghenv_lib.py       # Shared utilities library
│   └── logs/              # Log files directory
├── tests/                 # Test suite
│   └── test_ghenv_lib.py  # Comprehensive unit tests
└── data/                  # Optional folder to hold data files
    ├── *.yml.vars         # GitHub Actions variable files
    └── *.yml.secs         # GitHub Actions secret files
```

## Variables and Secrets Files

### Variable Files

Each `.vars` file contains a list of variable names, one per line

- Validation is case sensitive, but you can use any case for values
- Comments are allowed using hash (#)

```
# Example: myworkflow.yml.vars
MY_VARIABLE_A
MY_VARIABLE_B
MY_VARIABLE_C
myVariableD
```

### Secret Files

Each `.secs` file contains a list of secret names, one per line

- Validation is case sensitive, but you can use any case for values
- Comments are allowed using hash (#)

```
# Example: myworkflow.yml.secs
MY_SECRET_A
MY_SECRET_B
MY_SECRET_C
mySecretD
```

### File Naming Convention

Any file with a .vars or .secs extension will be processed. The following naming convention is suggested to match one file to each GitHub workflow / action file.

- `{{github-workflow-filename}}.yml.vars`
- `{{github-workflow-filename}}.yml.secs`

For example, a `.github/workflows/mydeploy.yml` would have matching files in `/data` called:

- `data/mydeploy.yml.vars`
- `data/mydeploy.yml.secs`

## Best Practices

1. **Keep files focused**: Each `.vars` and `.secs` file should contain variables/secrets for a specific service or deployment
2. **Use descriptive names**: Variable and secret names should clearly indicate their purpose
3. **Separate concerns**: Keep variables and secrets in separate files for better organization
4. **Regular synchronization**: Run `check.py` regularly to ensure environments stay in sync
5. **CI/CD**: Run `check.py` as part of the workflow. This will allow the workflow/actions to fail early if variables/secrets are missing
6. **Review extra items**: Periodically review and remove unused variables and secrets from GitHub environments
7. **Security**: Never commit actual secret values to version control - only secret names

## Scripts

### check.py

A Python script that checks that GitHub Environments have all the secrets and variables required for GitHub Actions and Workflows. Identifies missing secrets/variables as well as orphaned ones.

#### Features

- **Multi-file Support**: Scans a directory for all `.vars` and `.secs` files
- **Deduplication**: Automatically removes duplicate variable and secret names across files
- **Bidirectional Checking**:
  - Checks if all variables in `.vars` files exist in GitHub
  - Checks if all variables in GitHub exist in `.vars` files
  - Checks if all secrets in `.secs` files exist in GitHub
  - Checks if all secrets in GitHub exist in `.secs` files
- **Pagination Support**: Handles GitHub API pagination to check all variables and secrets
- **Comprehensive Logging**: Detailed logging with timestamps to both console and file

#### Usage

```bash
# Set your GitHub token
export GH_API_SECRET="your_github_token"

# Check all .vars and .secs files in a directory against a GitHub environment
uv run ghenv-check <owner> <repo> <env-name> <data-directory>

# Alternative methods:
uv run python -m ghenv.check <owner> <repo> <env-name> <data-directory>
uv run python src/ghenv/check.py <owner> <repo> <env-name> <data-directory>
```

#### Parameters

- `owner`: GitHub organization or username
- `repo`: Repository name
- `env-name`: GitHub environment name (e.g., `prd`, `staging`, `develop`)
- `data-directory`: Directory containing `.vars` and `.secs` files

#### Example

```bash
# Check all .vars and .secs files in the data directory against GitHub environment
uv run ghenv-check myorg myrepo myEnvName data
```

#### Makefile example

```makefile
envcheck:
	@uv run ghenv-check ${OWNER} ${REPO} ${GH_ENV_NAME} ghenv/data

# Alternative using module syntax
envcheck-alt:
	@uv run python -m ghenv.check ${OWNER} ${REPO} ${GH_ENV_NAME} ghenv/data
```

#### Prerequisites

- **Python 3.10+**: Required for running the scripts
- **uv**: Package manager for Python (install from https://docs.astral.sh/uv/)
- **GitHub Token**: Must have `actions:write` permission

#### Output

The script provides detailed output including:

1. **File Discovery**: Lists all `.vars` and `.secs` files found
2. **Variable Processing**: Shows deduplication progress for variables
3. **Secret Processing**: Shows deduplication progress for secrets
4. **GitHub Checking**: Reports on each variable and secret check
5. **Summary**: Categorized results with actionable suggestions for both variables and secrets

#### Exit Codes

- `0`: All variables and secrets are synchronized
- `1`: Variables or secrets are missing or extra items exist

#### Logging

The script logs to both console and `check.log` file with timestamps:

```
2024-01-15 14:30:25 | check | INFO | Found 3 .vars file(s): ['app1.yml.vars', 'app2.yml.vars', 'app3.yml.vars']
2024-01-15 14:30:26 | check | ERROR | MY_VAR is missing from GitHub environment production
```

#### Related Scripts

- `create.py`: Add missing variables and secrets to GitHub environments

### create.py

Create missing secrets and variables in GitHub environments with default placeholder values.

#### Features

- **Multi-file Support**: Scans a directory for all `.vars` and `.secs` files
- **Deduplication**: Automatically removes duplicate variable and secret names across files
- **Creates missing secrets and variables**:
  - Creates secrets with default encrypted value of `NONE`
  - Creates variables with default value of `NONE`
- **Encryption**: Automatically encrypts secrets using GitHub's public key
- **Comprehensive Logging**: Detailed logging with timestamps to both console and file

#### Usage

```bash
# Set your GitHub token
export GH_API_SECRET="your_github_token"

# Create missing variables and secrets in a GitHub environment
uv run ghenv-create <owner> <repo> <env-name> <data-directory>

# Alternative methods:
uv run python -m ghenv.create <owner> <repo> <env-name> <data-directory>
uv run python src/ghenv/create.py <owner> <repo> <env-name> <data-directory>
```

#### Parameters

- `owner`: GitHub organization or username
- `repo`: Repository name
- `env-name`: GitHub environment name (e.g., `prd`, `staging`, `develop`)
- `data-directory`: Directory containing `.vars` and `.secs` files

#### Example

```bash
# Create missing variables and secrets in the data directory for GitHub environment
uv run ghenv-create myorg myrepo myEnvName data
```

#### Makefile example

```makefile
envcreate:
	@uv run ghenv-create ${OWNER} ${REPO} ${GH_ENV_NAME} ghenv/data

# Alternative using module syntax
envcreate-alt:
	@uv run python -m ghenv.create ${OWNER} ${REPO} ${GH_ENV_NAME} ghenv/data
```

#### Prerequisites

- **Python 3.10+**: Required for running the scripts
- **uv**: Package manager for Python (install from https://docs.astral.sh/uv/)
- **GitHub Token**: Must have `actions:write` permission

#### Output

The script provides detailed output including:

1. **File Discovery**: Lists all `.vars` and `.secs` files found
2. **Variable Creation**: Shows progress for each variable being created
3. **Secret Creation**: Shows progress for each secret being created
4. **Summary**: Confirmation of completion

#### Exit Codes

- `0`: All variables and secrets created successfully
- `1`: Error occurred during creation

#### Logging

The script logs to both console and `create.log` file with timestamps:

```
2024-01-15 14:30:25 | create | INFO | Fetching environment public key...
2024-01-15 14:30:26 | create | INFO | Creating variable MY_VAR...
2024-01-15 14:30:27 | create | INFO | Variable MY_VAR created.
```

#### Related Scripts

- `check.py`: Identify missing or orphaned environment variables and secrets

## Installation

### Prerequisites

1. **Python 3.10 or higher**
2. **uv package manager** - Install from https://docs.astral.sh/uv/
3. **GitHub Token with `actions:write` permission**

### Setup

1. **Clone the repository**:

   ```bash
   git clone <repository-url>
   cd ghenv
   ```

2. **Install dependencies and the package**:

   ```bash
   # Sync all dependencies (including test dependencies)
   uv sync --all-extras

   # Or sync only production dependencies
   uv sync
   ```

3. **Set your GitHub token**:
   ```bash
   export GH_API_SECRET="your_github_token"
   ```

### Verifying Installation

```bash
# Verify the CLI commands are available
uv run ghenv-check --help
uv run ghenv-create --help

# Run tests to ensure everything is working
uv run pytest
```

## Troubleshooting

### Common Issues

1. **"Please set GH_API_SECRET"**

   ```bash
   export GH_API_SECRET="your_github_token"
   ```

2. **"No .vars / .secs files found"**

   - Ensure the directory path is correct
   - Check that files have `.vars` or `.secs` extension
   - Verify file permissions

3. **API Errors**

   - Verify GitHub token has correct permissions
   - Verify GitHub token has not expired
   - Check repository and environment names

4. **Python Import Errors**

   - Ensure all dependencies are installed: `uv sync --all-extras`
   - Check Python version: `python --version` (should be 3.10+)
   - Verify uv is installed: `uv --version`

5. **Logging Issues**
   - Check file permissions for log files
   - Ensure the log directory exists and is writable

### Environment Variables

- `GH_API_SECRET`: GitHub token with `actions:write` permission (required)
- `LOG_LEVEL`: Logging level (optional, defaults to INFO)

## Development

### Project Structure

- `src/ghenv/check.py`: Main script for checking environment synchronization
- `src/ghenv/create.py`: Main script for creating missing variables and secrets
- `src/ghenv/ghenv_lib.py`: Shared utilities and GitHub API functions
- `tests/test_ghenv_lib.py`: Comprehensive unit tests
- `pyproject.toml`: Project configuration and dependencies
- `uv.lock`: Locked dependencies for reproducible builds
- `data/`: Directory containing `.vars` and `.secs` files

### Development Commands

```bash
# Install all dependencies including test dependencies
uv sync --all-extras

# Run all tests
uv run pytest

# Run tests with verbose output
uv run pytest -v

# Run tests with coverage
uv run pytest --cov=ghenv --cov-report=html

# Build the package
uv build

# Add a new dependency
uv add <package-name>

# Add a test dependency
uv add --optional test <package-name>
```

### Adding New Features

1. **Shared Functions**: Add common functionality to `src/ghenv/ghenv_lib.py`
2. **Scripts**: Create new scripts in `src/ghenv/` that import from `ghenv_lib.py`
3. **Tests**: Add tests to `tests/test_ghenv_lib.py` following the existing patterns
4. **Logging**: Use the `setup_logging()` function for consistent logging
5. **Error Handling**: Follow the established pattern of logging errors and exiting with appropriate codes
6. **CLI Commands**: Add new entry points in `pyproject.toml` under `[project.scripts]`

### Running Tests

See the [CLAUDE.md](CLAUDE.md) file for comprehensive testing instructions and development commands.
