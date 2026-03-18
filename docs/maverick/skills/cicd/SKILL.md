---
title: CI/CD -- Project Implementation
topic: cicd
last-verified: 2026-03-18
status: recommended
---

## Stack

No CI/CD pipeline detected. Recommended: GitHub Actions, given the project is a GitHub-focused tool that manages GitHub environment variables and secrets. The pipeline should use `astral-sh/setup-uv` for uv installation and run on Python 3.10+.

## Configuration

Recommended pipeline stages following best-practice guidance: a validate stage running linting and type checking, a test stage running `uv run pytest`, and optionally a publish stage for PyPI releases. The `GH_API_SECRET` token should be provided via GitHub Actions secrets for any integration testing against real GitHub environments. The pipeline should trigger on push to main/develop and on pull requests.

## Patterns

Recommended workflow structure: a single workflow file with jobs for lint, test, and optionally publish. Use `uv sync --all-extras` for dependency installation with uv cache enabled. Pin the Python version to 3.10 (minimum supported). Run tests with `uv run pytest --cov=ghenv` to enforce coverage. The CLAUDE.md already documents the CI/CD integration pattern with `astral-sh/setup-uv` and `uv run ghenv-check`.

## File Locations

No CI/CD files exist. Recommended location: `.github/workflows/ci.yml` for the main pipeline. The project's CLAUDE.md already contains a sample GitHub Actions step under the "CI/CD Integration" section that can serve as a starting point.
