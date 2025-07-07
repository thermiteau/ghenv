#!/usr/bin/env python3
"""
GitHub Environment Variable Checker

This script checks GitHub environment variables and secrets against local .vars and .secs files
to ensure synchronization between the local configuration and the GitHub environment.

The script performs bidirectional checking:
- Checks if all variables/secrets in local files exist in GitHub
- Checks if all variables/secrets in GitHub exist in local files
- Reports missing items and orphaned items

The script supports:
- Multiple .vars and .secs files in a directory
- Automatic deduplication of variable/secret names
- Pagination support for large environments
- Comprehensive logging with timestamps
- Detailed error reporting

Usage:
    python check.py <owner> <repo> <env-name> <data-directory>

Example:
    python check.py myorg myrepo production data/

Dependencies:
    - GitHub token with 'actions:write' permission (set as GH_API_SECRET)
    - Python packages: requests (see requirements.txt)

Author: GitHub Environment Management Team
"""

import argparse
import sys

from ghenv.ghenv_lib import (
    check_secret_exists,
    check_variable_exists,
    find_files_by_extension,
    get_environment_secrets,
    get_environment_variables,
    read_variable_names,
    setup_logging,
    validate_environment,
)

# Initialize logging for this script
logger = setup_logging("check.log", "check")


def main():
    """
    Main function for checking GitHub environment variables and secrets.

    This function:
    1. Parses command line arguments
    2. Validates the environment and token
    3. Finds .vars and .secs files in the specified directory
    4. Checks variables and secrets against GitHub environment
    5. Reports missing and orphaned items
    6. Exits with appropriate status code

    Command line arguments:
        owner: GitHub repository owner (username or organization)
        repo: GitHub repository name
        env_name: GitHub environment name (e.g., 'production', 'staging')
        vars_dir: Directory containing .vars and .secs files

    Environment variables:
        GH_API_SECRET: GitHub token with 'actions:write' permission (required)
        LOG_LEVEL: Logging level (optional, defaults to INFO)

    Exit codes:
        0: Success - environment is synchronized
        1: Error - missing or orphaned items found, or validation failed
    """
    # Set up command line argument parsing
    parser = argparse.ArgumentParser(
        description="Check GitHub environment variables and secrets against local files."
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

    # Check if any files were found
    if not var_files and not sec_files:
        logger.error(f"No .vars or .secs files found in {vars_dir}")
        sys.exit(1)

    # Track if any issues are found during checking
    has_issues = False

    # Process variables (.vars files)
    if var_files:
        # Read and deduplicate variable names from all .vars files
        var_names = read_variable_names(var_files)

        # Track missing and existing variables
        missing_vars = []
        existing_vars = []

        # Check each variable against the GitHub environment
        for var_name in var_names:
            if check_variable_exists(
                args.owner, args.repo, args.env_name, gh_token, var_name
            ):
                existing_vars.append(var_name)
            else:
                missing_vars.append(var_name)

        # Get all variables from GitHub environment (with pagination support)
        github_vars = get_environment_variables(
            args.owner, args.repo, args.env_name, gh_token, logger
        )

        # Find variables that exist in GitHub but not in local files
        extra_vars = [var for var in github_vars if var not in var_names]

        # Report any issues found with variables
        if missing_vars or extra_vars:
            has_issues = True

            # Report missing variables (in files but not in GitHub)
            if missing_vars:
                for var in missing_vars:
                    logger.error(
                        f"{var} is missing from GitHub environment {args.env_name}"
                    )

            # Report extra variables (in GitHub but not in files)
            if extra_vars:
                for var in extra_vars:
                    logger.error(
                        f"{var} is in GitHub environment {args.env_name} but not in any .vars file"
                    )

    # Process secrets (.secs files)
    if sec_files:
        # Read and deduplicate secret names from all .secs files
        sec_names = read_variable_names(sec_files)

        # Track missing and existing secrets
        missing_secs = []
        existing_secs = []

        # Check each secret against the GitHub environment
        for sec_name in sec_names:
            if check_secret_exists(
                args.owner, args.repo, args.env_name, gh_token, sec_name
            ):
                existing_secs.append(sec_name)
            else:
                missing_secs.append(sec_name)

        # Get all secrets from GitHub environment (with pagination support)
        github_secs = get_environment_secrets(
            args.owner, args.repo, args.env_name, gh_token, logger
        )

        # Find secrets that exist in GitHub but not in local files
        extra_secs = [sec for sec in github_secs if sec not in sec_names]

        # Report any issues found with secrets
        if missing_secs or extra_secs:
            has_issues = True

            # Report missing secrets (in files but not in GitHub)
            if missing_secs:
                for sec in missing_secs:
                    logger.error(
                        f"{sec} is missing from GitHub environment {args.env_name}"
                    )

            # Report extra secrets (in GitHub but not in files)
            if extra_secs:
                for sec in extra_secs:
                    logger.error(
                        f"{sec} is in GitHub environment {args.env_name} but not in any .secs file"
                    )

    # Final status check and exit
    if has_issues:
        # Log error and exit with failure code if issues were found
        logger.error("Issues found - environment is not synchronized")
        sys.exit(1)
    else:
        # Log success message if everything is synchronized
        logger.info(f"Environment {args.env_name} is synchronized")


if __name__ == "__main__":
    # Only run the main function if this script is executed directly
    # This allows the script to be imported as a module without running main()
    main()
