#!/usr/bin/env python3
"""
GitHub Environment Variable Deleter

This script deletes orphaned environment variables and secrets from GitHub environments
that do not exist in local .vars and .secs files. It is the reverse of create.py.

The script:
- Identifies variables/secrets in GitHub that are not defined in local files
- Deletes these orphaned items from the GitHub environment
- Helps maintain synchronization between local configuration and GitHub

The script supports:
- Multiple .vars and .secs files in a directory
- Automatic deduplication of variable/secret names
- Pagination support for large environments
- Comprehensive logging with timestamps
- Dry-run mode for previewing changes

Usage:
    python delete.py <owner> <repo> <env-name> <data-directory> [--dry-run]

Example:
    python delete.py myorg myrepo production data/
    python delete.py myorg myrepo production data/ --dry-run

Dependencies:
    - GitHub token with 'actions:write' permission (set as GH_API_SECRET)
    - Python packages: requests (see requirements.txt)

Author: GitHub Environment Management Team
"""

import argparse
import sys

try:
    from .ghenv_lib import (
        delete_secret,
        delete_variable,
        find_files_by_extension,
        get_environment_secrets,
        get_environment_variables,
        read_variable_names,
        setup_logging,
        validate_environment,
    )
except ImportError:
    from ghenv_lib import (
        delete_secret,
        delete_variable,
        find_files_by_extension,
        get_environment_secrets,
        get_environment_variables,
        read_variable_names,
        setup_logging,
        validate_environment,
    )


def main():
    """
    Main function for deleting orphaned GitHub environment variables and secrets.

    This function:
    1. Parses command line arguments
    2. Validates the environment and token
    3. Finds .vars and .secs files in the specified directory
    4. Identifies orphaned variables and secrets in GitHub
    5. Deletes orphaned items (or previews in dry-run mode)
    6. Logs the results

    Command line arguments:
        owner: GitHub repository owner (username or organization)
        repo: GitHub repository name
        env_name: GitHub environment name (e.g., 'production', 'staging')
        vars_dir: Directory containing .vars and .secs files
        --dry-run: Preview deletions without actually deleting

    Environment variables:
        GH_API_SECRET: GitHub token with 'actions:write' permission (required)
        LOG_LEVEL: Logging level (optional, defaults to INFO)

    Exit codes:
        0: Success - all orphaned items deleted (or none found)
        1: Error - validation failed or API errors occurred
    """
    # Initialize logging for this script
    logger = setup_logging("delete.log", "delete")

    # Set up command line argument parsing
    parser = argparse.ArgumentParser(
        description="Delete orphaned GitHub environment variables and secrets not in local files."
    )
    parser.add_argument("owner", help="GitHub repository owner (username or organization)")
    parser.add_argument("repo", help="GitHub repository name")
    parser.add_argument("env_name", help="GitHub environment name (e.g., production, staging)")
    parser.add_argument("vars_dir", help="Directory containing .vars and .secs files")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview deletions without actually deleting",
    )

    # Parse the command line arguments
    args = parser.parse_args()

    # Validate environment and get GitHub token
    # This checks for GH_API_SECRET and validates the variables directory
    gh_token, vars_dir = validate_environment(args.vars_dir, logger)

    # Find all .vars and .secs files in the specified directory
    # This searches recursively for files with these extensions
    var_files = find_files_by_extension(vars_dir, "vars")
    sec_files = find_files_by_extension(vars_dir, "secs")

    # Check if any files were found
    if not var_files and not sec_files:
        logger.error(f"No .vars or .secs files found in {vars_dir}")
        sys.exit(1)

    # Track total deletions
    total_deleted = 0

    # Process variables (.vars files)
    if var_files:
        # Read and deduplicate variable names from all .vars files
        var_names = read_variable_names(var_files)
        var_names_set = set(var_names)

        # Get all variables from GitHub environment
        github_vars = get_environment_variables(
            args.owner, args.repo, args.env_name, gh_token, logger
        )
        github_vars_set = set(github_vars)

        # Find orphaned variables (in GitHub but not in local files)
        orphaned_vars = sorted(github_vars_set - var_names_set)

        if orphaned_vars:
            if args.dry_run:
                logger.info(f"[DRY-RUN] Would delete {len(orphaned_vars)} orphaned variable(s):")
                for var in orphaned_vars:
                    logger.info(f"[DRY-RUN]   - {var}")
            else:
                logger.info(f"Deleting {len(orphaned_vars)} orphaned variable(s)")
                for var in orphaned_vars:
                    delete_variable(args.owner, args.repo, args.env_name, gh_token, var, logger)
                    total_deleted += 1
        else:
            logger.info("No orphaned variables found")
    else:
        # No .vars files found, get all GitHub variables as potentially orphaned
        github_vars = get_environment_variables(
            args.owner, args.repo, args.env_name, gh_token, logger
        )
        if github_vars:
            logger.warning(
                f"No .vars files found but {len(github_vars)} variable(s) exist in GitHub. "
                "Skipping variable deletion (create .vars files to manage variables)."
            )

    # Process secrets (.secs files)
    if sec_files:
        # Read and deduplicate secret names from all .secs files
        sec_names = read_variable_names(sec_files)
        sec_names_set = set(sec_names)

        # Get all secrets from GitHub environment
        github_secs = get_environment_secrets(
            args.owner, args.repo, args.env_name, gh_token, logger
        )
        github_secs_set = set(github_secs)

        # Find orphaned secrets (in GitHub but not in local files)
        orphaned_secs = sorted(github_secs_set - sec_names_set)

        if orphaned_secs:
            if args.dry_run:
                logger.info(f"[DRY-RUN] Would delete {len(orphaned_secs)} orphaned secret(s):")
                for sec in orphaned_secs:
                    logger.info(f"[DRY-RUN]   - {sec}")
            else:
                logger.info(f"Deleting {len(orphaned_secs)} orphaned secret(s)")
                for sec in orphaned_secs:
                    delete_secret(args.owner, args.repo, args.env_name, gh_token, sec, logger)
                    total_deleted += 1
        else:
            logger.info("No orphaned secrets found")
    else:
        # No .secs files found, get all GitHub secrets as potentially orphaned
        github_secs = get_environment_secrets(
            args.owner, args.repo, args.env_name, gh_token, logger
        )
        if github_secs:
            logger.warning(
                f"No .secs files found but {len(github_secs)} secret(s) exist in GitHub. "
                "Skipping secret deletion (create .secs files to manage secrets)."
            )

    # Log completion message
    if args.dry_run:
        logger.info("[DRY-RUN] No changes made")
    else:
        logger.info(f"Deletion complete! Removed {total_deleted} item(s)")


if __name__ == "__main__":
    # Only run the main function if this script is executed directly
    # This allows the script to be imported as a module without running main()
    main()
