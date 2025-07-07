# GitHub Environment Variable Management

This directory contains Python scripts for managing GitHub environment variables across multiple deployment configurations.

## File Structure

```
ghenv/
├── README.md              # This documentation
├── check.py               # Check environment for secrets/variables
├── create.py              # Create missing secrets/variables
├── ghenv_lib.py           # Shared utilities library
├── data/                  # Optional folder to hold data files
   ├── *.yml.vars          # GitHub Actions variable files
   └── *.yml.secs          # GitHub Actions secret files
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
python check.py <owner> <repo> <env-name> <data-directory>
```

#### Parameters

- `owner`: GitHub organization or username
- `repo`: Repository name
- `env-name`: GitHub environment name (e.g., `prd`, `staging`, `develop`)
- `data-directory`: Directory containing `.vars` and `.secs` files

#### Example

```bash
# Check all .vars and .secs files in the data directory against GitHub environment
python check.py myorg myrepo myEnvName data
```

#### Makefile example

```makefile
envcheck:
	@python ghenv/check.py ${OWNER} ${REPO} ${GH_ENV_NAME} ghenv/data
```

#### Prerequisites

- **Python 3.6+**: Required for running the scripts
- **GitHub Token**: Must have `actions:write` permission
- **Python Dependencies**: Install via `pip install -r requirements.txt`

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
python create.py <owner> <repo> <env-name> <data-directory>
```

#### Parameters

- `owner`: GitHub organization or username
- `repo`: Repository name
- `env-name`: GitHub environment name (e.g., `prd`, `staging`, `develop`)
- `data-directory`: Directory containing `.vars` and `.secs` files

#### Example

```bash
# Create missing variables and secrets in the data directory for GitHub environment
python create.py myorg myrepo myEnvName data
```

#### Makefile example

```makefile
envcreate:
	@python ghenv/create.py ${OWNER} ${REPO} ${GH_ENV_NAME} ghenv/data
```

#### Prerequisites

- **Python 3.6+**: Required for running the scripts
- **GitHub Token**: Must have `actions:write` permission
- **Python Dependencies**: Install via `pip install -r requirements.txt`

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

1. **Python 3.6 or higher**
2. **GitHub Token with `actions:write` permission**

### Setup

1. **Clone the repository**:

   ```bash
   git clone <repository-url>
   cd ghenv
   ```

2. **Install Python dependencies**:

   ```bash
   pip install -r requirements.txt
   ```

3. **Set your GitHub token**:
   ```bash
   export GH_API_SECRET="your_github_token"
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

   - Ensure all dependencies are installed: `pip install -r requirements.txt`
   - Check Python version: `python --version` (should be 3.6+)

5. **Logging Issues**
   - Check file permissions for log files
   - Ensure the log directory exists and is writable

### Environment Variables

- `GH_API_SECRET`: GitHub token with `actions:write` permission (required)
- `LOG_LEVEL`: Logging level (optional, defaults to INFO)

## Development

### Project Structure

- `check.py`: Main script for checking environment synchronization
- `create.py`: Main script for creating missing variables and secrets
- `ghenv_lib.py`: Shared utilities and GitHub API functions
- `requirements.txt`: Python dependencies
- `data/`: Directory containing `.vars` and `.secs` files

### Adding New Features

1. **Shared Functions**: Add common functionality to `ghenv_lib.py`
2. **Scripts**: Create new scripts that import from `ghenv_lib.py`
3. **Logging**: Use the `setup_logging()` function for consistent logging
4. **Error Handling**: Follow the established pattern of logging errors and exiting with appropriate codes
