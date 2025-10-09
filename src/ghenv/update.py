#!/usr/bin/env python3
"""
GitHub Environment Variable Updater

This script updates existing environment variables and secrets in GitHub environments
from a single file. It reads variable names and values from the file and updates them
in the specified GitHub environment.

The script supports:
- Text files (.txt) with key=value pairs (one per line)
- JSON files (.json) with AWS CDK output format (camelCase keys converted to UPPER_SNAKE_CASE)
- Encrypted secret updates using GitHub's public key
- Comprehensive logging with timestamps
- Error handling and validation

Usage:
    python update.py <owner> <repo> <env-name> <file-path>

Example:
    python update.py myorg myrepo production data/config.txt
    python update.py myorg myrepo production data/cdk-output.json

File Formats:

    .txt file (key=value pairs):
        DB_HOST=localhost
        API_KEY=my_secret_key
        DB_PORT=5432
        # Comments are supported

    .json file (AWS CDK output format):
        {
          "stack-name": {
            "apiServerLambdaName": "my-lambda-function",
            "bucketName": "my-bucket"
          }
        }

        The camelCase keys will be converted to UPPER_SNAKE_CASE:
        apiServerLambdaName -> API_SERVER_LAMBDA_NAME
        bucketName -> BUCKET_NAME

Dependencies:
    - GitHub token with 'actions:write' permission (set as GH_API_SECRET)
    - Python packages: requests, pynacl (see requirements.txt)

Author: GitHub Environment Management Team
"""

import argparse
import sys

try:
    from .ghenv_lib import (
        encrypt_secret,
        fetch_public_key,
        get_environment_secrets,
        get_environment_variables,
        read_value_pairs,
        setup_logging,
        update_secret,
        update_variable,
    )
except ImportError:
    from ghenv_lib import (
        encrypt_secret,
        fetch_public_key,
        get_environment_secrets,
        get_environment_variables,
        read_value_pairs,
        setup_logging,
        update_secret,
        update_variable,
    )

# Initialize logging for this script
logger = setup_logging("update.log", "update")


def main():
    """
    Main function for updating GitHub environment variables and secrets.

    This function:
    1. Parses command line arguments
    2. Validates the environment and token
    3. Reads the input file (.txt or .json)
    4. Fetches the GitHub environment's public key for secret encryption
    5. Updates variables and secrets with values from the file
    6. Logs the results

    Command line arguments:
        owner: GitHub repository owner (username or organization)
        repo: GitHub repository name
        env_name: GitHub environment name (e.g., 'production', 'staging')
        file_path: Path to file containing values (.txt or .json)

    Environment variables:
        GH_API_SECRET: GitHub token with 'actions:write' permission (required)
        LOG_LEVEL: Logging level (optional, defaults to INFO)

    Exit codes:
        0: Success - all variables and secrets updated
        1: Error - validation failed or API errors occurred
    """
    # Set up command line argument parsing
    parser = argparse.ArgumentParser(
        description="Update GitHub environment variables and secrets from a file (.txt or .json)."
    )
    parser.add_argument(
        "owner", help="GitHub repository owner (username or organization)"
    )
    parser.add_argument("repo", help="GitHub repository name")
    parser.add_argument(
        "env_name", help="GitHub environment name (e.g., production, staging)"
    )
    parser.add_argument("file_path", help="Path to file containing values (.txt or .json)")

    # Parse the command line arguments
    args = parser.parse_args()

    # Validate that GitHub token is set
    import os
    from pathlib import Path

    gh_token = os.getenv("GH_API_SECRET")
    if not gh_token:
        logger.error(
            "Please set GH_API_SECRET to a GitHub token with 'actions:write' permission"
        )
        sys.exit(1)

    # Validate that the file exists
    file_path = Path(args.file_path)
    if not file_path.is_file():
        logger.error(f"File not found: {file_path}")
        sys.exit(1)

    # Read all name=value pairs from the file
    try:
        value_pairs = read_value_pairs(file_path)
    except Exception as e:
        logger.error(f"Error reading file {file_path}: {e}")
        sys.exit(1)

    if not value_pairs:
        logger.error("No valid name=value pairs found in file")
        sys.exit(1)

    # Fetch the public key needed for encrypting secrets
    # This is required by GitHub's API for storing secrets securely
    key_id, public_key = fetch_public_key(
        args.owner, args.repo, args.env_name, gh_token, logger
    )

    # Get existing variables and secrets from GitHub
    github_vars = get_environment_variables(
        args.owner, args.repo, args.env_name, gh_token, logger
    )
    github_secs = get_environment_secrets(
        args.owner, args.repo, args.env_name, gh_token, logger
    )

    github_vars_set = set(github_vars)
    github_secs_set = set(github_secs)

    # Track counts for reporting
    updated_vars = 0
    updated_secs = 0
    skipped_items = 0

    # Process each name=value pair
    for name, value in value_pairs.items():
        # Check if it's a variable (exists in GitHub variables)
        if name in github_vars_set:
            update_variable(
                args.owner, args.repo, args.env_name, gh_token, name, value, logger
            )
            updated_vars += 1
        # Check if it's a secret (exists in GitHub secrets)
        elif name in github_secs_set:
            # Encrypt the value using GitHub's public key
            encrypted_value = encrypt_secret(public_key, value)

            # Update the secret in GitHub
            update_secret(
                args.owner,
                args.repo,
                args.env_name,
                gh_token,
                name,
                encrypted_value,
                key_id,
                logger,
            )
            updated_secs += 1
        else:
            # Item doesn't exist in GitHub environment
            logger.warning(
                f"'{name}' does not exist in GitHub environment {args.env_name}, skipping"
            )
            skipped_items += 1

    # Log summary
    logger.info(
        f"Update complete: {updated_vars} variable(s), {updated_secs} secret(s)"
    )
    if skipped_items > 0:
        logger.info(f"Skipped {skipped_items} item(s) that don't exist in GitHub")


if __name__ == "__main__":
    # Only run the main function if this script is executed directly
    # This allows the script to be imported as a module without running main()
    main()
