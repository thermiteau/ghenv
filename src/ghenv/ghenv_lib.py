#!/usr/bin/env python3
"""
GitHub Environment Variable Management Library

This module provides shared utilities for managing GitHub environment variables
and secrets across multiple deployment configurations.

Functions:
    setup_logging: Configure logging with timestamps and dual output
    read_variable_names: Read and deduplicate variable/secret names from files
    read_value_pairs: Read and parse name=value pairs from files (.txt or .json)
    camel_to_upper_snake: Convert camelCase to UPPER_SNAKE_CASE
    find_files_by_extension: Find files by extension in directory
    fetch_public_key: Get public key for secret encryption
    encrypt_secret: Encrypt secrets using public key
    put_variable: Create variables in GitHub environment
    put_secret: Create secrets in GitHub environment
    update_variable: Update existing variables in GitHub environment
    update_secret: Update existing secrets in GitHub environment
    delete_variable: Delete variables from GitHub environment
    delete_secret: Delete secrets from GitHub environment
    check_variable_exists: Check if variable exists
    check_secret_exists: Check if secret exists
    get_environment_variables: Get all variables with pagination
    get_environment_secrets: Get all secrets with pagination
    validate_environment: Common environment validation
"""

import base64
import json
import logging
import os
import re
import sys
from collections.abc import Sequence
from logging import Logger
from pathlib import Path

import requests
from nacl import public

# GitHub API base URL
GITHUB_API = "https://api.github.com"

# Timeout in seconds for all HTTP requests to the GitHub API
_REQUEST_TIMEOUT = 30

# Maximum number of pages to fetch during pagination (safety limit)
_MAX_PAGES = 100


def _build_headers(token: str) -> dict[str, str]:
    """Build standard GitHub API request headers."""
    return {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def setup_logging(log_filename: str, logger_name: str) -> Logger:
    """
    Setup logging with timestamp format and both file and console handlers.

    Configures a named logger with file and console output. Unlike
    logging.basicConfig, this can be called multiple times for different
    loggers without interference.

    Args:
        log_filename (str): Name of the log file (or absolute path)
        logger_name (str): Name for the logger instance

    Returns:
        logging.Logger: Configured logger instance

    Example:
        >>> logger = setup_logging("app.log", "myapp")
        >>> logger.info("Application started")
    """
    # Get log level from environment variable, default to INFO
    log_level = os.environ.get("LOG_LEVEL", "INFO").upper()

    log_dir = os.path.join(os.path.dirname(__file__), "logs")
    os.makedirs(log_dir, exist_ok=True)

    logger = logging.getLogger(logger_name)
    logger.setLevel(log_level)

    # Avoid adding duplicate handlers if called multiple times with the same name
    if not logger.handlers:
        formatter = logging.Formatter(
            "%(asctime)s | %(name)s | %(levelname)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

        file_handler = logging.FileHandler(os.path.join(log_dir, log_filename))
        file_handler.setFormatter(formatter)

        stream_handler = logging.StreamHandler(sys.stdout)
        stream_handler.setFormatter(formatter)

        logger.addHandler(file_handler)
        logger.addHandler(stream_handler)

    return logger


def read_variable_names(file_paths: Sequence[Path | str]) -> list[str]:
    """
    Read and deduplicate variable/secret names from files.

    This function reads multiple files and extracts variable/secret names,
    removing duplicates and comments. Each line should contain one variable
    name, and lines starting with # are treated as comments.

    Args:
        file_paths (list): List of file paths to read from

    Returns:
        list: Sorted list of unique variable/secret names

    Example:
        >>> files = ["app1.vars", "app2.vars"]
        >>> names = read_variable_names(files)
        >>> print(names)
        ['DB_HOST', 'DB_PASSWORD', 'API_KEY']
    """
    var_names = set()

    # Process each file in the list
    for path in file_paths:
        with open(path) as f:
            for line in f:
                # Remove comments (everything after #)
                line = line.split("#")[0].strip()
                # Add non-empty lines to the set
                if line:
                    var_names.add(line)

    # Return sorted list for consistent ordering
    return sorted(var_names)


def find_files_by_extension(directory: Path | str, extension: str) -> list[Path]:
    """
    Find all files with given extension in directory.

    Recursively searches the directory and all subdirectories for files
    with the specified extension.

    Args:
        directory (str or Path): Directory to search in
        extension (str): File extension to search for (without dot)

    Returns:
        list: List of Path objects for matching files

    Example:
        >>> files = find_files_by_extension("data", "vars")
        >>> print([f.name for f in files])
        ['app1.yml.vars', 'app2.yml.vars']
    """
    return list(Path(directory).rglob(f"*.{extension}"))


def fetch_public_key(
    owner: str, repo: str, env_name: str, token: str, logger: Logger
) -> tuple[str, str]:
    """
    Fetch the public key for encrypting secrets.

    Retrieves the public key from GitHub that is required for encrypting
    secrets before sending them to the GitHub API.

    Args:
        owner (str): GitHub repository owner (username or organization)
        repo (str): GitHub repository name
        env_name (str): GitHub environment name
        token (str): GitHub API token
        logger (logging.Logger): Logger instance for output

    Returns:
        tuple: (key_id, public_key) - The key ID and base64-encoded public key

    Raises:
        SystemExit: If the API request fails

    Example:
        >>> key_id, public_key = fetch_public_key("myorg", "myrepo", "prod", token, logger)
        >>> print(f"Key ID: {key_id}")
    """
    logger.info("Fetching environment public key...")

    # Construct the API URL for the public key endpoint
    url = f"{GITHUB_API}/repos/{owner}/{repo}/environments/{env_name}/secrets/public-key"

    # Make the API request
    response = requests.get(url, headers=_build_headers(token), timeout=_REQUEST_TIMEOUT)

    # Check for successful response
    if response.status_code != 200:
        logger.error(
            f"Failed to fetch public key. Status: {response.status_code}, "
            f"Response: {response.text}"
        )
        sys.exit(1)

    # Parse the response and extract key information
    data = response.json()
    return data["key_id"], data["key"]


def encrypt_secret(public_key_base64: str, secret_value: str) -> str:
    """
    Encrypt a secret value using the public key.

    Uses libsodium (via PyNaCl) to encrypt the secret value with the
    provided public key. This is required by GitHub's API for storing secrets.

    Args:
        public_key_base64 (str): Base64-encoded public key from GitHub
        secret_value (str): The secret value to encrypt

    Returns:
        str: Base64-encoded encrypted secret value

    Example:
        >>> encrypted = encrypt_secret(public_key, "my_secret_value")
        >>> print(f"Encrypted: {encrypted}")
    """
    # Decode the base64 public key and create a PublicKey object
    public_key = public.PublicKey(base64.b64decode(public_key_base64))

    # Create a SealedBox for encryption (anonymous encryption)
    sealed_box = public.SealedBox(public_key)

    # Encrypt the secret value
    encrypted = sealed_box.encrypt(secret_value.encode())

    # Return the encrypted value as base64 string
    return base64.b64encode(encrypted).decode()


def put_variable(
    owner: str,
    repo: str,
    env_name: str,
    token: str,
    var_name: str,
    logger: Logger,
) -> None:
    """
    Create a variable in the GitHub environment.

    Creates a new environment variable in the specified GitHub environment.
    Variables are stored in plain text (unlike secrets which are encrypted).

    Args:
        owner (str): GitHub repository owner (username or organization)
        repo (str): GitHub repository name
        env_name (str): GitHub environment name
        token (str): GitHub API token
        var_name (str): Name of the variable to create
        logger (logging.Logger): Logger instance for output

    Raises:
        SystemExit: If the API request fails

    Example:
        >>> put_variable("myorg", "myrepo", "prod", token, "DB_HOST", logger)
        >>> # Creates a variable named DB_HOST in the prod environment
    """
    logger.info(f"Creating variable '{var_name}'...")

    # Construct the API URL for creating variables
    url = f"{GITHUB_API}/repos/{owner}/{repo}/environments/{env_name}/variables"

    # Prepare the request payload
    payload = {"name": var_name, "value": "NONE"}

    # Make the API request (POST for creating new variables)
    response = requests.post(
        url, headers=_build_headers(token), json=payload, timeout=_REQUEST_TIMEOUT
    )

    # Check for successful response (200 = updated, 201 = created)
    if response.status_code in (200, 201):
        logger.info(f"Variable '{var_name}' created.")
    elif response.status_code == 409:
        # Variable already exists - this is okay, just log a warning and continue
        logger.warning(f"Variable '{var_name}' already exists, skipping creation.")
    else:
        # Other errors should still cause the script to exit
        logger.error(
            f"Error creating variable '{var_name}' at {url}: "
            f"{response.status_code} {response.text}"
        )
        sys.exit(1)


def put_secret(
    owner: str,
    repo: str,
    env_name: str,
    token: str,
    sec_name: str,
    encrypted_value: str,
    key_id: str,
    logger: Logger,
) -> None:
    """
    Create a secret in the GitHub environment.

    Creates a new environment secret in the specified GitHub environment.
    Secrets must be encrypted with the environment's public key before
    being sent to the GitHub API.

    Args:
        owner (str): GitHub repository owner (username or organization)
        repo (str): GitHub repository name
        env_name (str): GitHub environment name
        token (str): GitHub API token
        sec_name (str): Name of the secret to create
        encrypted_value (str): Base64-encoded encrypted secret value
        key_id (str): Key ID used for encryption
        logger (logging.Logger): Logger instance for output

    Raises:
        SystemExit: If the API request fails

    Example:
        >>> put_secret("myorg", "myrepo", "prod", token, "DB_PASSWORD",
        ...     encrypted_value, key_id, logger)
        >>> # Creates an encrypted secret named DB_PASSWORD in the prod environment
    """
    logger.info(f"Creating secret '{sec_name}'...")

    # Construct the API URL for creating secrets
    url = f"{GITHUB_API}/repos/{owner}/{repo}/environments/{env_name}/secrets/{sec_name}"

    # Prepare the request payload with encrypted value and key ID
    payload = {"encrypted_value": encrypted_value, "key_id": key_id}

    # Make the API request (PUT for creating/updating secrets)
    response = requests.put(
        url, headers=_build_headers(token), json=payload, timeout=_REQUEST_TIMEOUT
    )

    # Check for successful response (200 = updated, 201 = created)
    if response.status_code in (200, 201):
        logger.info(f"Secret '{sec_name}' created.")
    elif response.status_code == 409:
        # Secret already exists - this is okay, just log a warning and continue
        logger.warning(f"Secret '{sec_name}' already exists, skipping creation.")
    else:
        # Other errors should still cause the script to exit
        # Response body omitted to avoid leaking secret-related data
        logger.error(f"Error creating secret '{sec_name}': {response.status_code}")
        sys.exit(1)


def check_variable_exists(owner: str, repo: str, env_name: str, token: str, var_name: str) -> bool:
    """
    Check if a variable exists in the GitHub environment.

    Makes a GET request to the GitHub API to check if a specific
    environment variable exists.

    Args:
        owner (str): GitHub repository owner (username or organization)
        repo (str): GitHub repository name
        env_name (str): GitHub environment name
        token (str): GitHub API token
        var_name (str): Name of the variable to check

    Returns:
        bool: True if the variable exists, False otherwise

    Example:
        >>> exists = check_variable_exists("myorg", "myrepo", "prod", token, "DB_HOST")
        >>> print(f"DB_HOST exists: {exists}")
    """
    # Construct the API URL for checking the specific variable
    url = f"{GITHUB_API}/repos/{owner}/{repo}/environments/{env_name}/variables/{var_name}"

    # Make the API request
    response = requests.get(url, headers=_build_headers(token), timeout=_REQUEST_TIMEOUT)

    # Return True if the variable exists (200 status), False otherwise
    return response.status_code == 200


def check_secret_exists(owner: str, repo: str, env_name: str, token: str, sec_name: str) -> bool:
    """
    Check if a secret exists in the GitHub environment.

    Makes a GET request to the GitHub API to check if a specific
    environment secret exists.

    Args:
        owner (str): GitHub repository owner (username or organization)
        repo (str): GitHub repository name
        env_name (str): GitHub environment name
        token (str): GitHub API token
        sec_name (str): Name of the secret to check

    Returns:
        bool: True if the secret exists, False otherwise

    Example:
        >>> exists = check_secret_exists("myorg", "myrepo", "prod", token, "DB_PASSWORD")
        >>> print(f"DB_PASSWORD exists: {exists}")
    """
    # Construct the API URL for checking the specific secret
    url = f"{GITHUB_API}/repos/{owner}/{repo}/environments/{env_name}/secrets/{sec_name}"

    # Make the API request
    response = requests.get(url, headers=_build_headers(token), timeout=_REQUEST_TIMEOUT)

    # Return True if the secret exists (200 status), False otherwise
    return response.status_code == 200


def get_environment_variables(
    owner: str, repo: str, env_name: str, token: str, logger: Logger
) -> list[str]:
    """
    Get all variables from GitHub environment with pagination.

    Retrieves all environment variables from the specified GitHub environment,
    handling pagination automatically to get all variables regardless of count.

    Args:
        owner (str): GitHub repository owner (username or organization)
        repo (str): GitHub repository name
        env_name (str): GitHub environment name
        token (str): GitHub API token
        logger (logging.Logger): Logger instance for output

    Returns:
        list: List of variable names in the environment

    Raises:
        SystemExit: If the API request fails

    Example:
        >>> variables = get_environment_variables("myorg", "myrepo", "prod", token, logger)
        >>> print(f"Found {len(variables)} variables: {variables}")
    """
    all_variables = []
    page = 1
    per_page = 100  # Maximum items per page for GitHub API
    headers = _build_headers(token)

    # Loop through all pages until no more results
    while page <= _MAX_PAGES:
        # Construct the API URL with pagination parameters
        url = (
            f"{GITHUB_API}/repos/{owner}/{repo}/environments/{env_name}"
            f"/variables?per_page={per_page}&page={page}"
        )

        # Make the API request
        response = requests.get(url, headers=headers, timeout=_REQUEST_TIMEOUT)

        # Check for successful response
        if response.status_code != 200:
            logger.error(
                f"Failed to get environment variables: {response.status_code} {response.text}"
            )
            sys.exit(1)

        # Parse the response
        data = response.json()
        variables = data.get("variables", [])

        # If no variables returned, we've reached the end
        if not variables:
            break

        # Extract variable names and add to our list
        all_variables.extend([var["name"] for var in variables])
        page += 1
    else:
        logger.warning(
            f"Pagination limit reached ({_MAX_PAGES} pages). Results may be incomplete."
        )

    return all_variables


def get_environment_secrets(
    owner: str, repo: str, env_name: str, token: str, logger: Logger
) -> list[str]:
    """
    Get all secrets from GitHub environment with pagination.

    Retrieves all environment secrets from the specified GitHub environment,
    handling pagination automatically to get all secrets regardless of count.

    Args:
        owner (str): GitHub repository owner (username or organization)
        repo (str): GitHub repository name
        env_name (str): GitHub environment name
        token (str): GitHub API token
        logger (logging.Logger): Logger instance for output

    Returns:
        list: List of secret names in the environment

    Raises:
        SystemExit: If the API request fails

    Example:
        >>> secrets = get_environment_secrets("myorg", "myrepo", "prod", token, logger)
        >>> print(f"Found {len(secrets)} secrets: {secrets}")
    """
    all_secrets = []
    page = 1
    per_page = 100  # Maximum items per page for GitHub API
    headers = _build_headers(token)

    # Loop through all pages until no more results
    while page <= _MAX_PAGES:
        # Construct the API URL with pagination parameters
        url = (
            f"{GITHUB_API}/repos/{owner}/{repo}/environments/{env_name}"
            f"/secrets?per_page={per_page}&page={page}"
        )

        # Make the API request
        response = requests.get(url, headers=headers, timeout=_REQUEST_TIMEOUT)

        # Check for successful response
        if response.status_code != 200:
            logger.error(
                f"Failed to get environment secrets: {response.status_code} {response.text}"
            )
            sys.exit(1)

        # Parse the response
        data = response.json()
        secrets = data.get("secrets", [])

        # If no secrets returned, we've reached the end
        if not secrets:
            break

        # Extract secret names and add to our list
        all_secrets.extend([secret["name"] for secret in secrets])
        page += 1
    else:
        logger.warning(
            f"Pagination limit reached ({_MAX_PAGES} pages). Results may be incomplete."
        )

    return all_secrets


def camel_to_upper_snake(camel_str: str) -> str:
    """
    Convert camelCase string to UPPER_SNAKE_CASE.

    This function converts camelCase strings to uppercase snake_case format,
    which is commonly used for environment variable names. Handles acronyms
    correctly (e.g., HTTPSPort -> HTTPS_PORT).

    Args:
        camel_str (str): String in camelCase format

    Returns:
        str: String converted to UPPER_SNAKE_CASE

    Example:
        >>> camel_to_upper_snake("apiServerLambdaName")
        'API_SERVER_LAMBDA_NAME'
        >>> camel_to_upper_snake("HTTPSPort")
        'HTTPS_PORT'
    """
    # First pass: insert underscore between consecutive uppercase and uppercase+lowercase
    # e.g., "HTTPSPort" -> "HTTPS_Port"
    snake_str = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", camel_str)
    # Second pass: insert underscore between lowercase and uppercase
    # e.g., "apiServer" -> "api_Server"
    snake_str = re.sub(r"([a-z])([A-Z])", r"\1_\2", snake_str)
    # Convert to uppercase
    return snake_str.upper()


def read_value_pairs(file_path: Path | str, logger: Logger | None = None) -> dict[str, str]:
    """
    Read and parse name=value pairs from file.

    This function reads a file and extracts name=value pairs.
    Supports two file formats:
    - .txt files: key=value pairs (one per line, # for comments)
    - .json files: AWS CDK output format (camelCase keys converted to UPPER_SNAKE_CASE)

    Args:
        file_path (str or Path): Path to file to read from
        logger (logging.Logger, optional): Logger for warnings about skipped lines

    Returns:
        dict: Dictionary of name:value pairs

    Example:
        >>> # .txt file
        >>> pairs = read_value_pairs("app1.txt")
        >>> print(pairs)
        {'DB_HOST': 'localhost', 'DB_PASSWORD': 'secret123', 'API_KEY': 'key456'}

        >>> # .json file (CDK output)
        >>> pairs = read_value_pairs("cdk-output.json")
        >>> print(pairs)
        {'API_SERVER_LAMBDA_NAME': 'somestring', 'WEBSOCKET_SERVER_LAMBDA_NAME': 'somestring'}
    """
    file_path = Path(file_path)
    value_pairs = {}

    # Determine file type by extension
    if file_path.suffix.lower() == ".json":
        # Parse JSON file (AWS CDK output format)
        with open(file_path) as f:
            data = json.load(f)

        # CDK output has a top-level key (e.g., "some-app") with nested object
        # We need to extract the nested object and transform keys
        for _top_level_key, nested_obj in data.items():
            if isinstance(nested_obj, dict):
                # Transform camelCase keys to UPPER_SNAKE_CASE
                for camel_key, value in nested_obj.items():
                    snake_key = camel_to_upper_snake(camel_key)
                    value_pairs[snake_key] = str(value)

    elif file_path.suffix.lower() == ".txt":
        # Parse text file (key=value format)
        with open(file_path) as f:
            for line_num, line in enumerate(f, start=1):
                # Remove comments (everything after #)
                line = line.split("#")[0].strip()
                # Skip empty lines
                if not line:
                    continue
                # Parse name=value pairs
                if "=" in line:
                    name, value = line.split("=", 1)  # Split on first = only
                    name = name.strip()
                    value = value.strip()
                    if name and value:
                        value_pairs[name] = value
                    elif name and not value and logger:
                        logger.warning(
                                f"Skipping '{name}' at {file_path}:{line_num}: empty value"
                            )
                else:
                    if logger:
                        logger.warning(
                            f"Skipping line {line_num} in {file_path}: "
                            f"no '=' found in '{line}'"
                        )
    else:
        raise ValueError(
            f"Unsupported file format: {file_path.suffix}. Only .txt and .json are supported."
        )

    return value_pairs


def update_variable(
    owner: str,
    repo: str,
    env_name: str,
    token: str,
    var_name: str,
    var_value: str,
    logger: Logger,
) -> None:
    """
    Update a variable in the GitHub environment.

    Updates an existing environment variable in the specified GitHub environment.
    Variables are stored in plain text (unlike secrets which are encrypted).

    Args:
        owner (str): GitHub repository owner (username or organization)
        repo (str): GitHub repository name
        env_name (str): GitHub environment name
        token (str): GitHub API token
        var_name (str): Name of the variable to update
        var_value (str): New value for the variable
        logger (logging.Logger): Logger instance for output

    Raises:
        SystemExit: If the API request fails

    Example:
        >>> update_variable("myorg", "myrepo", "prod", token, "DB_HOST", "db.example.com", logger)
        >>> # Updates the DB_HOST variable in the prod environment
    """
    logger.info(f"Updating variable '{var_name}'...")

    # Construct the API URL for updating variables
    url = f"{GITHUB_API}/repos/{owner}/{repo}/environments/{env_name}/variables/{var_name}"

    # Prepare the request payload
    payload = {"name": var_name, "value": var_value}

    # Make the API request (PATCH for updating existing variables)
    response = requests.patch(
        url, headers=_build_headers(token), json=payload, timeout=_REQUEST_TIMEOUT
    )

    # Check for successful response (204 = updated successfully)
    if response.status_code == 204:
        logger.info(f"Variable '{var_name}' updated successfully.")
    else:
        # Log error and exit on failure
        logger.error(
            f"Error updating variable '{var_name}' at {url}: "
            f"{response.status_code} {response.text}"
        )
        sys.exit(1)


def update_secret(
    owner: str,
    repo: str,
    env_name: str,
    token: str,
    sec_name: str,
    encrypted_value: str,
    key_id: str,
    logger: Logger,
) -> None:
    """
    Update a secret in the GitHub environment.

    Updates an existing environment secret in the specified GitHub environment.
    Secrets must be encrypted with the environment's public key before
    being sent to the GitHub API. This function uses PUT which creates or updates.

    Args:
        owner (str): GitHub repository owner (username or organization)
        repo (str): GitHub repository name
        env_name (str): GitHub environment name
        token (str): GitHub API token
        sec_name (str): Name of the secret to update
        encrypted_value (str): Base64-encoded encrypted secret value
        key_id (str): Key ID used for encryption
        logger (logging.Logger): Logger instance for output

    Raises:
        SystemExit: If the API request fails

    Example:
        >>> update_secret("myorg", "myrepo", "prod", token, "DB_PASSWORD",
        ...     encrypted_value, key_id, logger)
        >>> # Updates the encrypted secret named DB_PASSWORD in the prod environment
    """
    logger.info(f"Updating secret '{sec_name}'...")

    # Construct the API URL for updating secrets
    url = f"{GITHUB_API}/repos/{owner}/{repo}/environments/{env_name}/secrets/{sec_name}"

    # Prepare the request payload with encrypted value and key ID
    payload = {"encrypted_value": encrypted_value, "key_id": key_id}

    # Make the API request (PUT for updating secrets)
    response = requests.put(
        url, headers=_build_headers(token), json=payload, timeout=_REQUEST_TIMEOUT
    )

    # Check for successful response (201 = created, 204 = updated)
    if response.status_code in (201, 204):
        logger.info(f"Secret '{sec_name}' updated successfully.")
    else:
        # Response body omitted to avoid leaking secret-related data
        logger.error(f"Error updating secret '{sec_name}': {response.status_code}")
        sys.exit(1)


def delete_variable(
    owner: str,
    repo: str,
    env_name: str,
    token: str,
    var_name: str,
    logger: Logger,
) -> None:
    """
    Delete a variable from the GitHub environment.

    Deletes an existing environment variable from the specified GitHub environment.

    Args:
        owner (str): GitHub repository owner (username or organization)
        repo (str): GitHub repository name
        env_name (str): GitHub environment name
        token (str): GitHub API token
        var_name (str): Name of the variable to delete
        logger (logging.Logger): Logger instance for output

    Raises:
        SystemExit: If the API request fails

    Example:
        >>> delete_variable("myorg", "myrepo", "prod", token, "DB_HOST", logger)
        >>> # Deletes the variable named DB_HOST from the prod environment
    """
    logger.info(f"Deleting variable '{var_name}'...")

    # Construct the API URL for deleting the variable
    url = f"{GITHUB_API}/repos/{owner}/{repo}/environments/{env_name}/variables/{var_name}"

    # Make the API request (DELETE for removing variables)
    response = requests.delete(url, headers=_build_headers(token), timeout=_REQUEST_TIMEOUT)

    # Check for successful response (204 = deleted successfully)
    if response.status_code == 204:
        logger.info(f"Variable '{var_name}' deleted successfully.")
    elif response.status_code == 404:
        # Variable doesn't exist - log a warning but don't fail
        logger.warning(f"Variable '{var_name}' not found, skipping deletion.")
    else:
        # Log error and exit on failure
        logger.error(
            f"Error deleting variable '{var_name}' at {url}: "
            f"{response.status_code} {response.text}"
        )
        sys.exit(1)


def delete_secret(
    owner: str,
    repo: str,
    env_name: str,
    token: str,
    sec_name: str,
    logger: Logger,
) -> None:
    """
    Delete a secret from the GitHub environment.

    Deletes an existing environment secret from the specified GitHub environment.

    Args:
        owner (str): GitHub repository owner (username or organization)
        repo (str): GitHub repository name
        env_name (str): GitHub environment name
        token (str): GitHub API token
        sec_name (str): Name of the secret to delete
        logger (logging.Logger): Logger instance for output

    Raises:
        SystemExit: If the API request fails

    Example:
        >>> delete_secret("myorg", "myrepo", "prod", token, "DB_PASSWORD", logger)
        >>> # Deletes the secret named DB_PASSWORD from the prod environment
    """
    logger.info(f"Deleting secret '{sec_name}'...")

    # Construct the API URL for deleting the secret
    url = f"{GITHUB_API}/repos/{owner}/{repo}/environments/{env_name}/secrets/{sec_name}"

    # Make the API request (DELETE for removing secrets)
    response = requests.delete(url, headers=_build_headers(token), timeout=_REQUEST_TIMEOUT)

    # Check for successful response (204 = deleted successfully)
    if response.status_code == 204:
        logger.info(f"Secret '{sec_name}' deleted successfully.")
    elif response.status_code == 404:
        # Secret doesn't exist - log a warning but don't fail
        logger.warning(f"Secret '{sec_name}' not found, skipping deletion.")
    else:
        # Response body omitted to avoid leaking secret-related data
        logger.error(f"Error deleting secret '{sec_name}': {response.status_code}")
        sys.exit(1)


def validate_environment(
    vars_dir: Path | str,
    logger: Logger,
) -> tuple[str, Path]:
    """
    Validate common environment setup and return token.

    Performs common validation tasks that are shared between scripts:
    - Checks if GitHub token is set
    - Validates that the variables directory exists
    - Returns the token and validated directory path

    Args:
        vars_dir (str): Directory containing .vars and .secs files
        logger (logging.Logger): Logger instance for output

    Returns:
        tuple: (gh_token, vars_dir) - The GitHub token and validated directory path

    Raises:
        SystemExit: If validation fails

    Example:
        >>> token, directory = validate_environment("data", logger)
        >>> print(f"Token: {token[:10]}..., Directory: {directory}")
    """
    # Check if GitHub token is set in environment
    gh_token = os.getenv("GH_API_SECRET")
    if not gh_token:
        logger.error("Please set GH_API_SECRET to a GitHub token with 'actions:write' permission")
        sys.exit(1)

    # Validate that the variables directory exists
    vars_dir = Path(vars_dir)
    if not vars_dir.is_dir():
        logger.error(f"Variables directory not found: {vars_dir}")
        sys.exit(1)

    return gh_token, vars_dir
