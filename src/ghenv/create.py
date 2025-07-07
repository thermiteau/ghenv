#!/usr/bin/env python3
"""
GitHub Environment Variable Creator

This script creates missing environment variables and secrets in GitHub environments
based on local .vars and .secs files. It reads variable and secret names from files
and creates them in the specified GitHub environment with placeholder values.

The script supports:
- Multiple .vars and .secs files in a directory
- Automatic deduplication of variable/secret names
- Encrypted secret creation using GitHub's public key
- Comprehensive logging with timestamps
- Error handling and validation

Usage:
    python create.py <owner> <repo> <env-name> <data-directory>

Example:
    python create.py myorg myrepo production data/

Dependencies:
    - GitHub token with 'actions:write' permission (set as GH_API_SECRET)
    - Python packages: requests, pynacl (see requirements.txt)

Author: GitHub Environment Management Team
"""

import argparse
import sys

from ghenv.ghenv_lib import (
    encrypt_secret,
    fetch_public_key,
    find_files_by_extension,
    put_secret,
    put_variable,
    read_variable_names,
    setup_logging,
    validate_environment,
)

# Initialize logging for this script
logger = setup_logging("create.log", "create")


def main():
    """
    Main function for creating GitHub environment variables and secrets.

    This function:
    1. Parses command line arguments
    2. Validates the environment and token
    3. Finds .vars and .secs files in the specified directory
    4. Fetches the GitHub environment's public key for secret encryption
    5. Creates missing variables and secrets with placeholder values
    6. Logs the results

    Command line arguments:
        owner: GitHub repository owner (username or organization)
        repo: GitHub repository name
        env_name: GitHub environment name (e.g., 'production', 'staging')
        vars_dir: Directory containing .vars and .secs files

    Environment variables:
        GH_API_SECRET: GitHub token with 'actions:write' permission (required)
        LOG_LEVEL: Logging level (optional, defaults to INFO)

    Exit codes:
        0: Success - all variables and secrets created
        1: Error - validation failed or API errors occurred
    """
    # Set up command line argument parsing
    parser = argparse.ArgumentParser(
        description="Create missing GitHub environment variables and secrets from local files."
    )
    parser.add_argument(
        "owner", help="GitHub repository owner (username or organization)"
    )
    parser.add_argument("repo", help="GitHub repository name")
    parser.add_argument(
        "env_name", help="GitHub environment name (e.g., production, staging)"
    )
    parser.add_argument("vars_dir", help="Directory containing .vars and .secs files")

    # Parse the command line arguments
    args = parser.parse_args()

    # Validate environment and get GitHub token
    # This checks for GH_API_SECRET and validates the variables directory
    gh_token, vars_dir = validate_environment(
        args.owner, args.repo, args.env_name, args.vars_dir, logger
    )

    # Find all .vars and .secs files in the specified directory
    # This searches recursively for files with these extensions
    var_files = find_files_by_extension(vars_dir, "vars")
    sec_files = find_files_by_extension(vars_dir, "secs")

    # Fetch the public key needed for encrypting secrets
    # This is required by GitHub's API for storing secrets securely
    key_id, public_key = fetch_public_key(
        args.owner, args.repo, args.env_name, gh_token, logger
    )

    # Check if any files were found
    if not var_files and not sec_files:
        logger.error(f"No .vars or .secs files found in {vars_dir}")
        sys.exit(1)

    # Process variables (.vars files)
    if var_files:
        # Read and deduplicate variable names from all .vars files
        var_names = read_variable_names(var_files)

        # Create each variable in the GitHub environment
        for var in var_names:
            logger.info(f"Creating variable {var}...")
            put_variable(args.owner, args.repo, args.env_name, gh_token, var, logger)

    # Process secrets (.secs files)
    if sec_files:
        # Read and deduplicate secret names from all .secs files
        sec_names = read_variable_names(sec_files)

        # Create each secret in the GitHub environment
        for sec in sec_names:
            # Encrypt the placeholder value using GitHub's public key
            encrypted_value = encrypt_secret(public_key, "NONE")  # Placeholder value

            # Create the secret in GitHub
            put_secret(
                args.owner,
                args.repo,
                args.env_name,
                gh_token,
                sec,
                encrypted_value,
                key_id,
                logger,
            )

    # Log completion message
    logger.info("Environment setup complete!")


if __name__ == "__main__":
    # Only run the main function if this script is executed directly
    # This allows the script to be imported as a module without running main()
    main()
