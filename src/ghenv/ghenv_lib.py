#!/usr/bin/env python3
"""
GitHub Environment Variable Management Library

This module provides shared utilities for managing GitHub environment variables
and secrets across multiple deployment configurations.

Functions:
    setup_logging: Configure logging with timestamps and dual output
    read_variable_names: Read and deduplicate variable/secret names from files
    find_files_by_extension: Find files by extension in directory
    fetch_public_key: Get public key for secret encryption
    encrypt_secret: Encrypt secrets using public key
    put_variable: Create variables in GitHub environment
    put_secret: Create secrets in GitHub environment
    check_variable_exists: Check if variable exists
    check_secret_exists: Check if secret exists
    get_environment_variables: Get all variables with pagination
    get_environment_secrets: Get all secrets with pagination
    validate_environment: Common environment validation
"""

import base64
import logging
import os
import sys
from pathlib import Path

import requests
from nacl import public

# GitHub API base URL
GITHUB_API = "https://api.github.com"


def setup_logging(log_file, logger_name):
    """
    Setup logging with timestamp format and both file and console handlers.

    Args:
        log_file (str): Path to the log file
        logger_name (str): Name for the logger instance

    Returns:
        logging.Logger: Configured logger instance

    Example:
        >>> logger = setup_logging("app.log", "myapp")
        >>> logger.info("Application started")
    """
    # Get log level from environment variable, default to INFO
    log_level = os.environ.get("LOG_LEVEL", "INFO")

    # Configure logging with custom format including timestamps
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s | %(name)s | %(levelname)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler(sys.stdout),
        ],
    )
    return logging.getLogger(logger_name)


def read_variable_names(file_paths):
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


def find_files_by_extension(directory, extension):
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


def fetch_public_key(owner, repo, env_name, token, logger):
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
    url = (
        f"{GITHUB_API}/repos/{owner}/{repo}/environments/{env_name}/secrets/public-key"
    )

    # Set up headers for the API request
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    # Make the API request
    response = requests.get(url, headers=headers)

    # Check for successful response
    if response.status_code != 200:
        logger.error(
            f"Failed to fetch public key. Status: {response.status_code}, Response: {response.text}"
        )
        sys.exit(1)

    # Parse the response and extract key information
    data = response.json()
    return data["key_id"], data["key"]


def encrypt_secret(public_key_base64, secret_value):
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


def put_variable(owner, repo, env_name, token, var_name, logger):
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

    # Set up headers for the API request
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    # Prepare the request payload
    payload = {"name": var_name, "value": "NONE"}

    # Make the API request (POST for creating new variables)
    response = requests.post(url, headers=headers, json=payload)

    # Check for successful response (200 = updated, 201 = created)
    if response.status_code not in (200, 201):
        logger.error(
            f"Error creating variable '{var_name}' at {url}: {response.status_code} {response.text}"
        )
        sys.exit(1)

    logger.info(f"Variable '{var_name}' created.")


def put_secret(owner, repo, env_name, token, sec_name, encrypted_value, key_id, logger):
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
        >>> put_secret("myorg", "myrepo", "prod", token, "DB_PASSWORD", encrypted_value, key_id, logger)
        >>> # Creates an encrypted secret named DB_PASSWORD in the prod environment
    """
    logger.info(f"Creating secret '{sec_name}'...")

    # Construct the API URL for creating secrets
    url = (
        f"{GITHUB_API}/repos/{owner}/{repo}/environments/{env_name}/secrets/{sec_name}"
    )

    # Set up headers for the API request
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    # Prepare the request payload with encrypted value and key ID
    payload = {"encrypted_value": encrypted_value, "key_id": key_id}

    # Make the API request (PUT for creating/updating secrets)
    response = requests.put(url, headers=headers, json=payload)

    # Check for successful response (200 = updated, 201 = created)
    if response.status_code not in (200, 201):
        logger.error(
            f"Error creating secret '{sec_name}': {response.status_code} {response.text}"
        )
        sys.exit(1)

    logger.info(f"Secret '{sec_name}' created.")


def check_variable_exists(owner, repo, env_name, token, var_name):
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

    # Set up headers for the API request
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    # Make the API request
    response = requests.get(url, headers=headers)

    # Return True if the variable exists (200 status), False otherwise
    return response.status_code == 200


def check_secret_exists(owner, repo, env_name, token, sec_name):
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
    url = (
        f"{GITHUB_API}/repos/{owner}/{repo}/environments/{env_name}/secrets/{sec_name}"
    )

    # Set up headers for the API request
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    # Make the API request
    response = requests.get(url, headers=headers)

    # Return True if the secret exists (200 status), False otherwise
    return response.status_code == 200


def get_environment_variables(owner, repo, env_name, token, logger):
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

    # Loop through all pages until no more results
    while True:
        # Construct the API URL with pagination parameters
        url = f"{GITHUB_API}/repos/{owner}/{repo}/environments/{env_name}/variables?per_page={per_page}&page={page}"

        # Set up headers for the API request
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
        }

        # Make the API request
        response = requests.get(url, headers=headers)

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

    return all_variables


def get_environment_secrets(owner, repo, env_name, token, logger):
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

    # Loop through all pages until no more results
    while True:
        # Construct the API URL with pagination parameters
        url = f"{GITHUB_API}/repos/{owner}/{repo}/environments/{env_name}/secrets?per_page={per_page}&page={page}"

        # Set up headers for the API request
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
        }

        # Make the API request
        response = requests.get(url, headers=headers)

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

    return all_secrets


def validate_environment(owner, repo, env_name, vars_dir, logger):
    """
    Validate common environment setup and return token.

    Performs common validation tasks that are shared between scripts:
    - Checks if GitHub token is set
    - Validates that the variables directory exists
    - Returns the token and validated directory path

    Args:
        owner (str): GitHub repository owner (username or organization)
        repo (str): GitHub repository name
        env_name (str): GitHub environment name
        vars_dir (str): Directory containing .vars and .secs files
        logger (logging.Logger): Logger instance for output

    Returns:
        tuple: (gh_token, vars_dir) - The GitHub token and validated directory path

    Raises:
        SystemExit: If validation fails

    Example:
        >>> token, directory = validate_environment("myorg", "myrepo", "prod", "data", logger)
        >>> print(f"Token: {token[:10]}..., Directory: {directory}")
    """
    # Check if GitHub token is set in environment
    gh_token = os.getenv("GH_API_SECRET")
    if not gh_token:
        logger.error(
            "Please set GH_API_SECRET to a GitHub token with 'actions:write' permission"
        )
        sys.exit(1)

    # Validate that the variables directory exists
    vars_dir = Path(vars_dir)
    if not vars_dir.is_dir():
        logger.error(f"Variables directory not found: {vars_dir}")
        sys.exit(1)

    return gh_token, vars_dir
