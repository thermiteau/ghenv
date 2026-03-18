#!/usr/bin/env python3
"""
Unit tests for ghenv_lib.py

This module contains comprehensive unit tests for all functions in the
GitHub Environment Variable Management Library.

Test Coverage:
    - setup_logging: Logging configuration and output
    - read_variable_names: File parsing and deduplication
    - find_files_by_extension: File discovery
    - fetch_public_key: GitHub API interaction
    - encrypt_secret: Secret encryption
    - put_variable: Variable creation
    - put_secret: Secret creation
    - delete_variable: Variable deletion
    - delete_secret: Secret deletion
    - check_variable_exists: Variable existence checking
    - check_secret_exists: Secret existence checking
    - get_environment_variables: Variable retrieval with pagination
    - get_environment_secrets: Secret retrieval with pagination
    - validate_environment: Environment validation
    - camel_to_upper_snake: Case conversion
    - read_value_pairs: File parsing for name=value pairs

Dependencies:
    - pytest
    - pytest-mock
    - requests-mock
    - tempfile
    - pathlib
"""

import base64
import json
import logging
import os

# Import the module under test
import sys
import tempfile
from unittest.mock import Mock, mock_open, patch

import pytest
from nacl import public

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
import ghenv.ghenv_lib as ghenv_lib


class TestSetupLogging:
    """Test cases for setup_logging function."""

    def test_setup_logging_creates_logger(self, tmp_path):
        """Test that setup_logging creates a properly configured logger."""
        log_file = tmp_path / "test.log"

        # Remove any existing handlers on this logger name
        existing = logging.getLogger("test_logger_creates")
        existing.handlers.clear()

        # Call the function
        logger = ghenv_lib.setup_logging(str(log_file), "test_logger_creates")

        # Verify logger was created
        assert isinstance(logger, logging.Logger)
        assert logger.name == "test_logger_creates"

        # Test that logging works
        test_message = "Test log message"
        logger.info(test_message)

        # Verify message appears in log file
        assert log_file.exists()
        with open(log_file) as f:
            log_content = f.read()
            assert test_message in log_content

    def test_setup_logging_console_output(self, capsys):
        """Test that setup_logging outputs to console."""
        with tempfile.NamedTemporaryFile() as tmp_file:
            # Remove any existing handlers on this logger name
            existing = logging.getLogger("console_test")
            existing.handlers.clear()

            logger = ghenv_lib.setup_logging(tmp_file.name, "console_test")

            test_message = "Console test message"
            logger.info(test_message)

            # Check console output
            captured = capsys.readouterr()
            assert test_message in captured.out

    def test_setup_logging_environment_level(self, tmp_path):
        """Test that setup_logging respects LOG_LEVEL environment variable."""
        log_file = tmp_path / "debug.log"

        # Remove any existing handlers on this logger name
        existing = logging.getLogger("debug_test")
        existing.handlers.clear()

        # Set environment variable
        with patch.dict(os.environ, {"LOG_LEVEL": "DEBUG"}):
            logger = ghenv_lib.setup_logging(str(log_file), "debug_test")

            # Test debug message (should be logged)
            logger.debug("Debug message")

            # Verify debug message appears
            with open(log_file) as f:
                log_content = f.read()
                assert "Debug message" in log_content

    def test_setup_logging_no_duplicate_handlers(self, tmp_path):
        """Test that calling setup_logging twice doesn't add duplicate handlers."""
        log_file = tmp_path / "nodup.log"
        logger_name = "nodup_test"

        # Remove any existing handlers
        existing = logging.getLogger(logger_name)
        existing.handlers.clear()

        logger1 = ghenv_lib.setup_logging(str(log_file), logger_name)
        handler_count = len(logger1.handlers)

        logger2 = ghenv_lib.setup_logging(str(log_file), logger_name)
        assert len(logger2.handlers) == handler_count
        assert logger1 is logger2


class TestReadVariableNames:
    """Test cases for read_variable_names function."""

    def test_read_variable_names_single_file(self):
        """Test reading variable names from a single file."""
        file_content = "VAR1\nVAR2\nVAR3\n"

        with patch("builtins.open", mock_open(read_data=file_content)):
            result = ghenv_lib.read_variable_names(["test.vars"])

        assert result == ["VAR1", "VAR2", "VAR3"]

    def test_read_variable_names_multiple_files(self):
        """Test reading variable names from multiple files with deduplication."""
        file1_content = "VAR1\nVAR2\nVAR3\n"
        file2_content = "VAR2\nVAR3\nVAR4\n"

        with patch("builtins.open") as mock_file:
            mock_file.side_effect = [
                mock_open(read_data=file1_content).return_value,
                mock_open(read_data=file2_content).return_value,
            ]

            result = ghenv_lib.read_variable_names(["file1.vars", "file2.vars"])

        # Should deduplicate and sort
        assert result == ["VAR1", "VAR2", "VAR3", "VAR4"]

    def test_read_variable_names_with_comments(self):
        """Test that comments are properly ignored."""
        file_content = "VAR1\n# This is a comment\nVAR2\nVAR3 # Inline comment\n"

        with patch("builtins.open", mock_open(read_data=file_content)):
            result = ghenv_lib.read_variable_names(["test.vars"])

        assert result == ["VAR1", "VAR2", "VAR3"]

    def test_read_variable_names_empty_lines(self):
        """Test that empty lines are ignored."""
        file_content = "VAR1\n\nVAR2\n  \nVAR3\n"

        with patch("builtins.open", mock_open(read_data=file_content)):
            result = ghenv_lib.read_variable_names(["test.vars"])

        assert result == ["VAR1", "VAR2", "VAR3"]

    def test_read_variable_names_empty_file(self):
        """Test reading from an empty file."""
        with patch("builtins.open", mock_open(read_data="")):
            result = ghenv_lib.read_variable_names(["empty.vars"])

        assert result == []


class TestFindFilesByExtension:
    """Test cases for find_files_by_extension function."""

    def test_find_files_by_extension_single_file(self, tmp_path):
        """Test finding a single file with specified extension."""
        # Create a test file
        test_file = tmp_path / "test.vars"
        test_file.write_text("content")

        result = ghenv_lib.find_files_by_extension(tmp_path, "vars")

        assert len(result) == 1
        assert result[0].name == "test.vars"

    def test_find_files_by_extension_multiple_files(self, tmp_path):
        """Test finding multiple files with specified extension."""
        # Create test files
        (tmp_path / "file1.vars").write_text("content1")
        (tmp_path / "file2.vars").write_text("content2")
        (tmp_path / "file3.txt").write_text("content3")  # Different extension

        result = ghenv_lib.find_files_by_extension(tmp_path, "vars")

        assert len(result) == 2
        file_names = [f.name for f in result]
        assert "file1.vars" in file_names
        assert "file2.vars" in file_names

    def test_find_files_by_extension_subdirectories(self, tmp_path):
        """Test finding files in subdirectories."""
        # Create directory structure
        subdir = tmp_path / "subdir"
        subdir.mkdir()

        (tmp_path / "file1.vars").write_text("content1")
        (subdir / "file2.vars").write_text("content2")

        result = ghenv_lib.find_files_by_extension(tmp_path, "vars")

        assert len(result) == 2
        file_names = [f.name for f in result]
        assert "file1.vars" in file_names
        assert "file2.vars" in file_names

    def test_find_files_by_extension_no_matches(self, tmp_path):
        """Test finding files when none match the extension."""
        (tmp_path / "file1.txt").write_text("content1")
        (tmp_path / "file2.txt").write_text("content2")

        result = ghenv_lib.find_files_by_extension(tmp_path, "vars")

        assert result == []


class TestFetchPublicKey:
    """Test cases for fetch_public_key function."""

    def test_fetch_public_key_success(self, requests_mock):
        """Test successful public key fetch."""
        mock_response = {"key_id": "test_key_id", "key": "test_public_key_base64"}

        requests_mock.get(
            "https://api.github.com/repos/testowner/testrepo/environments/testenv/secrets/public-key",
            json=mock_response,
            status_code=200,
        )

        logger = Mock()
        key_id, public_key = ghenv_lib.fetch_public_key(
            "testowner", "testrepo", "testenv", "test_token", logger
        )

        assert key_id == "test_key_id"
        assert public_key == "test_public_key_base64"
        logger.info.assert_called_once_with("Fetching environment public key...")

    def test_fetch_public_key_api_error(self, requests_mock):
        """Test public key fetch with API error."""
        requests_mock.get(
            "https://api.github.com/repos/testowner/testrepo/environments/testenv/secrets/public-key",
            status_code=404,
            text="Not found",
        )

        logger = Mock()

        with pytest.raises(SystemExit):
            ghenv_lib.fetch_public_key("testowner", "testrepo", "testenv", "test_token", logger)

        logger.error.assert_called_once()


class TestEncryptSecret:
    """Test cases for encrypt_secret function."""

    def test_encrypt_secret_success(self):
        """Test successful secret encryption."""
        # Generate a test key pair
        private_key = public.PrivateKey.generate()
        public_key = private_key.public_key
        public_key_base64 = base64.b64encode(bytes(public_key)).decode()

        secret_value = "test_secret_value"

        # Encrypt the secret
        encrypted = ghenv_lib.encrypt_secret(public_key_base64, secret_value)

        # Verify the result is a base64 string
        assert isinstance(encrypted, str)
        assert len(encrypted) > 0

        # Verify it can be decoded as base64
        try:
            base64.b64decode(encrypted)
        except Exception:
            pytest.fail("Encrypted value is not valid base64")

    def test_encrypt_secret_different_values(self):
        """Test that different secret values produce different encrypted results."""
        # Generate a test key pair
        private_key = public.PrivateKey.generate()
        public_key = private_key.public_key
        public_key_base64 = base64.b64encode(bytes(public_key)).decode()

        secret1 = "secret1"
        secret2 = "secret2"

        encrypted1 = ghenv_lib.encrypt_secret(public_key_base64, secret1)
        encrypted2 = ghenv_lib.encrypt_secret(public_key_base64, secret2)

        # Encrypted values should be different
        assert encrypted1 != encrypted2


class TestPutVariable:
    """Test cases for put_variable function."""

    def test_put_variable_success(self, requests_mock):
        """Test successful variable creation."""
        requests_mock.post(
            "https://api.github.com/repos/testowner/testrepo/environments/testenv/variables",
            status_code=201,
        )

        logger = Mock()
        ghenv_lib.put_variable(
            "testowner", "testrepo", "testenv", "test_token", "TEST_VAR", logger
        )

        # Verify the request was made correctly
        assert len(requests_mock.request_history) == 1
        request = requests_mock.request_history[0]
        assert request.method == "POST"
        assert request.json() == {"name": "TEST_VAR", "value": "NONE"}

        # Verify both log messages were called
        logger.info.assert_any_call("Creating variable 'TEST_VAR'...")
        logger.info.assert_any_call("Variable 'TEST_VAR' created.")

    def test_put_variable_already_exists(self, requests_mock):
        """Test variable creation when variable already exists (409)."""
        requests_mock.post(
            "https://api.github.com/repos/testowner/testrepo/environments/testenv/variables",
            status_code=409,
            json={"message": "Already exists"},
        )

        logger = Mock()

        # Should not raise SystemExit, should handle gracefully
        ghenv_lib.put_variable(
            "testowner", "testrepo", "testenv", "test_token", "TEST_VAR", logger
        )

        # Verify warning was logged
        logger.warning.assert_called_once_with(
            "Variable 'TEST_VAR' already exists, skipping creation."
        )

    def test_put_variable_api_error(self, requests_mock):
        """Test variable creation with API error."""
        requests_mock.post(
            "https://api.github.com/repos/testowner/testrepo/environments/testenv/variables",
            status_code=400,
            text="Bad request",
        )

        logger = Mock()

        with pytest.raises(SystemExit):
            ghenv_lib.put_variable(
                "testowner", "testrepo", "testenv", "test_token", "TEST_VAR", logger
            )

        logger.error.assert_called_once()


class TestPutSecret:
    """Test cases for put_secret function."""

    def test_put_secret_success(self, requests_mock):
        """Test successful secret creation."""
        requests_mock.put(
            "https://api.github.com/repos/testowner/testrepo/environments/testenv/secrets/TEST_SECRET",
            status_code=201,
        )

        logger = Mock()
        ghenv_lib.put_secret(
            "testowner",
            "testrepo",
            "testenv",
            "test_token",
            "TEST_SECRET",
            "encrypted_value",
            "key_id",
            logger,
        )

        # Verify the request was made correctly
        assert len(requests_mock.request_history) == 1
        request = requests_mock.request_history[0]
        assert request.method == "PUT"
        assert request.json() == {
            "encrypted_value": "encrypted_value",
            "key_id": "key_id",
        }

        # Verify both log messages were called
        logger.info.assert_any_call("Creating secret 'TEST_SECRET'...")
        logger.info.assert_any_call("Secret 'TEST_SECRET' created.")

    def test_put_secret_already_exists(self, requests_mock):
        """Test secret creation when secret already exists (409)."""
        requests_mock.put(
            "https://api.github.com/repos/testowner/testrepo/environments/testenv/secrets/TEST_SECRET",
            status_code=409,
            json={"message": "Already exists"},
        )

        logger = Mock()

        # Should not raise SystemExit, should handle gracefully
        ghenv_lib.put_secret(
            "testowner",
            "testrepo",
            "testenv",
            "test_token",
            "TEST_SECRET",
            "encrypted_value",
            "key_id",
            logger,
        )

        # Verify warning was logged
        logger.warning.assert_called_once_with(
            "Secret 'TEST_SECRET' already exists, skipping creation."
        )

    def test_put_secret_api_error(self, requests_mock):
        """Test secret creation with API error."""
        requests_mock.put(
            "https://api.github.com/repos/testowner/testrepo/environments/testenv/secrets/TEST_SECRET",
            status_code=400,
            text="Bad request",
        )

        logger = Mock()

        with pytest.raises(SystemExit):
            ghenv_lib.put_secret(
                "testowner",
                "testrepo",
                "testenv",
                "test_token",
                "TEST_SECRET",
                "encrypted_value",
                "key_id",
                logger,
            )

        logger.error.assert_called_once()

    def test_put_secret_error_does_not_log_response_body(self, requests_mock):
        """Test that secret creation error does not leak response body."""
        requests_mock.put(
            "https://api.github.com/repos/testowner/testrepo/environments/testenv/secrets/TEST_SECRET",
            status_code=500,
            text="sensitive payload echo",
        )

        logger = Mock()

        with pytest.raises(SystemExit):
            ghenv_lib.put_secret(
                "testowner",
                "testrepo",
                "testenv",
                "test_token",
                "TEST_SECRET",
                "encrypted_value",
                "key_id",
                logger,
            )

        error_msg = logger.error.call_args[0][0]
        assert "sensitive payload echo" not in error_msg
        assert "500" in error_msg


class TestDeleteVariable:
    """Test cases for delete_variable function."""

    def test_delete_variable_success(self, requests_mock):
        """Test successful variable deletion."""
        requests_mock.delete(
            "https://api.github.com/repos/testowner/testrepo/environments/testenv/variables/TEST_VAR",
            status_code=204,
        )

        logger = Mock()
        ghenv_lib.delete_variable(
            "testowner", "testrepo", "testenv", "test_token", "TEST_VAR", logger
        )

        # Verify the request was made correctly
        assert len(requests_mock.request_history) == 1
        request = requests_mock.request_history[0]
        assert request.method == "DELETE"

        # Verify both log messages were called
        logger.info.assert_any_call("Deleting variable 'TEST_VAR'...")
        logger.info.assert_any_call("Variable 'TEST_VAR' deleted successfully.")

    def test_delete_variable_not_found(self, requests_mock):
        """Test variable deletion when variable doesn't exist (404)."""
        requests_mock.delete(
            "https://api.github.com/repos/testowner/testrepo/environments/testenv/variables/TEST_VAR",
            status_code=404,
            json={"message": "Not found"},
        )

        logger = Mock()

        # Should not raise SystemExit, should handle gracefully
        ghenv_lib.delete_variable(
            "testowner", "testrepo", "testenv", "test_token", "TEST_VAR", logger
        )

        # Verify warning was logged
        logger.warning.assert_called_once_with("Variable 'TEST_VAR' not found, skipping deletion.")

    def test_delete_variable_api_error(self, requests_mock):
        """Test variable deletion with API error."""
        requests_mock.delete(
            "https://api.github.com/repos/testowner/testrepo/environments/testenv/variables/TEST_VAR",
            status_code=500,
            text="Internal server error",
        )

        logger = Mock()

        with pytest.raises(SystemExit):
            ghenv_lib.delete_variable(
                "testowner", "testrepo", "testenv", "test_token", "TEST_VAR", logger
            )

        logger.error.assert_called_once()


class TestDeleteSecret:
    """Test cases for delete_secret function."""

    def test_delete_secret_success(self, requests_mock):
        """Test successful secret deletion."""
        requests_mock.delete(
            "https://api.github.com/repos/testowner/testrepo/environments/testenv/secrets/TEST_SECRET",
            status_code=204,
        )

        logger = Mock()
        ghenv_lib.delete_secret(
            "testowner", "testrepo", "testenv", "test_token", "TEST_SECRET", logger
        )

        # Verify the request was made correctly
        assert len(requests_mock.request_history) == 1
        request = requests_mock.request_history[0]
        assert request.method == "DELETE"

        # Verify both log messages were called
        logger.info.assert_any_call("Deleting secret 'TEST_SECRET'...")
        logger.info.assert_any_call("Secret 'TEST_SECRET' deleted successfully.")

    def test_delete_secret_not_found(self, requests_mock):
        """Test secret deletion when secret doesn't exist (404)."""
        requests_mock.delete(
            "https://api.github.com/repos/testowner/testrepo/environments/testenv/secrets/TEST_SECRET",
            status_code=404,
            json={"message": "Not found"},
        )

        logger = Mock()

        # Should not raise SystemExit, should handle gracefully
        ghenv_lib.delete_secret(
            "testowner", "testrepo", "testenv", "test_token", "TEST_SECRET", logger
        )

        # Verify warning was logged
        logger.warning.assert_called_once_with(
            "Secret 'TEST_SECRET' not found, skipping deletion."
        )

    def test_delete_secret_api_error(self, requests_mock):
        """Test secret deletion with API error."""
        requests_mock.delete(
            "https://api.github.com/repos/testowner/testrepo/environments/testenv/secrets/TEST_SECRET",
            status_code=500,
            text="Internal server error",
        )

        logger = Mock()

        with pytest.raises(SystemExit):
            ghenv_lib.delete_secret(
                "testowner", "testrepo", "testenv", "test_token", "TEST_SECRET", logger
            )

        logger.error.assert_called_once()

    def test_delete_secret_error_does_not_log_response_body(self, requests_mock):
        """Test that secret deletion error does not leak response body."""
        requests_mock.delete(
            "https://api.github.com/repos/testowner/testrepo/environments/testenv/secrets/TEST_SECRET",
            status_code=500,
            text="sensitive data",
        )

        logger = Mock()

        with pytest.raises(SystemExit):
            ghenv_lib.delete_secret(
                "testowner", "testrepo", "testenv", "test_token", "TEST_SECRET", logger
            )

        error_msg = logger.error.call_args[0][0]
        assert "sensitive data" not in error_msg
        assert "500" in error_msg


class TestCheckVariableExists:
    """Test cases for check_variable_exists function."""

    def test_check_variable_exists_true(self, requests_mock):
        """Test checking for existing variable."""
        requests_mock.get(
            "https://api.github.com/repos/testowner/testrepo/environments/testenv/variables/TEST_VAR",
            status_code=200,
        )

        result = ghenv_lib.check_variable_exists(
            "testowner", "testrepo", "testenv", "test_token", "TEST_VAR"
        )

        assert result is True

    def test_check_variable_exists_false(self, requests_mock):
        """Test checking for non-existing variable."""
        requests_mock.get(
            "https://api.github.com/repos/testowner/testrepo/environments/testenv/variables/TEST_VAR",
            status_code=404,
        )

        result = ghenv_lib.check_variable_exists(
            "testowner", "testrepo", "testenv", "test_token", "TEST_VAR"
        )

        assert result is False


class TestCheckSecretExists:
    """Test cases for check_secret_exists function."""

    def test_check_secret_exists_true(self, requests_mock):
        """Test checking for existing secret."""
        requests_mock.get(
            "https://api.github.com/repos/testowner/testrepo/environments/testenv/secrets/TEST_SECRET",
            status_code=200,
        )

        result = ghenv_lib.check_secret_exists(
            "testowner", "testrepo", "testenv", "test_token", "TEST_SECRET"
        )

        assert result is True

    def test_check_secret_exists_false(self, requests_mock):
        """Test checking for non-existing secret."""
        requests_mock.get(
            "https://api.github.com/repos/testowner/testrepo/environments/testenv/secrets/TEST_SECRET",
            status_code=404,
        )

        result = ghenv_lib.check_secret_exists(
            "testowner", "testrepo", "testenv", "test_token", "TEST_SECRET"
        )

        assert result is False


class TestGetEnvironmentVariables:
    """Test cases for get_environment_variables function."""

    def test_get_environment_variables_single_page(self, requests_mock):
        """Test getting variables from a single page."""
        mock_response = {"variables": [{"name": "VAR1"}, {"name": "VAR2"}, {"name": "VAR3"}]}

        requests_mock.get(
            "https://api.github.com/repos/testowner/testrepo/environments/testenv/variables?per_page=100&page=1",
            json=mock_response,
            status_code=200,
        )
        # Add empty page 2 for loop termination
        requests_mock.get(
            "https://api.github.com/repos/testowner/testrepo/environments/testenv/variables?per_page=100&page=2",
            json={"variables": []},
            status_code=200,
        )

        logger = Mock()
        result = ghenv_lib.get_environment_variables(
            "testowner", "testrepo", "testenv", "test_token", logger
        )

        assert result == ["VAR1", "VAR2", "VAR3"]

    def test_get_environment_variables_multiple_pages(self, requests_mock):
        """Test getting variables from multiple pages."""
        # First page (full page)
        requests_mock.get(
            "https://api.github.com/repos/testowner/testrepo/environments/testenv/variables?per_page=100&page=1",
            json={"variables": [{"name": "VAR1"}, {"name": "VAR2"}]},
            status_code=200,
        )
        # Second page (partial page, indicating last page)
        requests_mock.get(
            "https://api.github.com/repos/testowner/testrepo/environments/testenv/variables?per_page=100&page=2",
            json={"variables": [{"name": "VAR3"}]},
            status_code=200,
        )
        # Add empty page 3 for loop termination
        requests_mock.get(
            "https://api.github.com/repos/testowner/testrepo/environments/testenv/variables?per_page=100&page=3",
            json={"variables": []},
            status_code=200,
        )

        logger = Mock()
        result = ghenv_lib.get_environment_variables(
            "testowner", "testrepo", "testenv", "test_token", logger
        )

        assert result == ["VAR1", "VAR2", "VAR3"]

    def test_get_environment_variables_empty(self, requests_mock):
        """Test getting variables from empty environment."""
        requests_mock.get(
            "https://api.github.com/repos/testowner/testrepo/environments/testenv/variables?per_page=100&page=1",
            json={"variables": []},
            status_code=200,
        )

        logger = Mock()
        result = ghenv_lib.get_environment_variables(
            "testowner", "testrepo", "testenv", "test_token", logger
        )

        assert result == []

    def test_get_environment_variables_api_error(self, requests_mock):
        """Test getting variables with API error."""
        requests_mock.get(
            "https://api.github.com/repos/testowner/testrepo/environments/testenv/variables?per_page=100&page=1",
            status_code=500,
            text="Internal server error",
        )

        logger = Mock()

        with pytest.raises(SystemExit):
            ghenv_lib.get_environment_variables(
                "testowner", "testrepo", "testenv", "test_token", logger
            )

        logger.error.assert_called_once()


class TestGetEnvironmentSecrets:
    """Test cases for get_environment_secrets function."""

    def test_get_environment_secrets_single_page(self, requests_mock):
        """Test getting secrets from a single page."""
        mock_response = {
            "secrets": [{"name": "SECRET1"}, {"name": "SECRET2"}, {"name": "SECRET3"}]
        }

        requests_mock.get(
            "https://api.github.com/repos/testowner/testrepo/environments/testenv/secrets?per_page=100&page=1",
            json=mock_response,
            status_code=200,
        )
        # Add empty page 2 for loop termination
        requests_mock.get(
            "https://api.github.com/repos/testowner/testrepo/environments/testenv/secrets?per_page=100&page=2",
            json={"secrets": []},
            status_code=200,
        )

        logger = Mock()
        result = ghenv_lib.get_environment_secrets(
            "testowner", "testrepo", "testenv", "test_token", logger
        )

        assert result == ["SECRET1", "SECRET2", "SECRET3"]

    def test_get_environment_secrets_multiple_pages(self, requests_mock):
        """Test getting secrets from multiple pages."""
        # First page (full page)
        requests_mock.get(
            "https://api.github.com/repos/testowner/testrepo/environments/testenv/secrets?per_page=100&page=1",
            json={"secrets": [{"name": "SECRET1"}, {"name": "SECRET2"}]},
            status_code=200,
        )
        # Second page (partial page, indicating last page)
        requests_mock.get(
            "https://api.github.com/repos/testowner/testrepo/environments/testenv/secrets?per_page=100&page=2",
            json={"secrets": [{"name": "SECRET3"}]},
            status_code=200,
        )
        # Add empty page 3 for loop termination
        requests_mock.get(
            "https://api.github.com/repos/testowner/testrepo/environments/testenv/secrets?per_page=100&page=3",
            json={"secrets": []},
            status_code=200,
        )

        logger = Mock()
        result = ghenv_lib.get_environment_secrets(
            "testowner", "testrepo", "testenv", "test_token", logger
        )

        assert result == ["SECRET1", "SECRET2", "SECRET3"]

    def test_get_environment_secrets_empty(self, requests_mock):
        """Test getting secrets from empty environment."""
        requests_mock.get(
            "https://api.github.com/repos/testowner/testrepo/environments/testenv/secrets?per_page=100&page=1",
            json={"secrets": []},
            status_code=200,
        )

        logger = Mock()
        result = ghenv_lib.get_environment_secrets(
            "testowner", "testrepo", "testenv", "test_token", logger
        )

        assert result == []

    def test_get_environment_secrets_api_error(self, requests_mock):
        """Test getting secrets with API error."""
        requests_mock.get(
            "https://api.github.com/repos/testowner/testrepo/environments/testenv/secrets?per_page=100&page=1",
            status_code=500,
            text="Internal server error",
        )

        logger = Mock()

        with pytest.raises(SystemExit):
            ghenv_lib.get_environment_secrets(
                "testowner", "testrepo", "testenv", "test_token", logger
            )

        logger.error.assert_called_once()


class TestValidateEnvironment:
    """Test cases for validate_environment function."""

    def test_validate_environment_success(self, tmp_path):
        """Test successful environment validation."""
        # Create a test directory
        test_dir = tmp_path / "test_data"
        test_dir.mkdir()

        with patch.dict(os.environ, {"GH_API_SECRET": "test_token"}):
            logger = Mock()
            token, directory = ghenv_lib.validate_environment(str(test_dir), logger)

        assert token == "test_token"
        assert directory == test_dir

    def test_validate_environment_no_token(self):
        """Test validation with missing GitHub token."""
        with patch.dict(os.environ, {}, clear=True):
            logger = Mock()

            with pytest.raises(SystemExit):
                ghenv_lib.validate_environment("test_dir", logger)

            logger.error.assert_called_once()

    def test_validate_environment_invalid_directory(self):
        """Test validation with non-existent directory."""
        with patch.dict(os.environ, {"GH_API_SECRET": "test_token"}):
            logger = Mock()

            with pytest.raises(SystemExit):
                ghenv_lib.validate_environment("/non/existent/path", logger)

            logger.error.assert_called_once()


class TestCamelToUpperSnake:
    """Test cases for camel_to_upper_snake function."""

    def test_simple_camel_case(self):
        """Test basic camelCase conversion."""
        assert ghenv_lib.camel_to_upper_snake("apiServerLambdaName") == "API_SERVER_LAMBDA_NAME"

    def test_single_word_lowercase(self):
        """Test single lowercase word."""
        assert ghenv_lib.camel_to_upper_snake("name") == "NAME"

    def test_single_word_uppercase(self):
        """Test single uppercase word."""
        assert ghenv_lib.camel_to_upper_snake("NAME") == "NAME"

    def test_acronym_at_start(self):
        """Test acronym at the start of the string."""
        assert ghenv_lib.camel_to_upper_snake("APIKey") == "API_KEY"

    def test_acronym_in_middle(self):
        """Test acronym in the middle of the string."""
        assert ghenv_lib.camel_to_upper_snake("myHTTPSClient") == "MY_HTTPS_CLIENT"

    def test_acronym_at_end(self):
        """Test acronym at the end of the string."""
        assert ghenv_lib.camel_to_upper_snake("useHTTPS") == "USE_HTTPS"

    def test_consecutive_uppercase_then_lowercase(self):
        """Test transition from consecutive uppercase to lowercase."""
        assert ghenv_lib.camel_to_upper_snake("HTTPSPort") == "HTTPS_PORT"

    def test_websocket_example(self):
        """Test the websocket example from docstring."""
        assert (
            ghenv_lib.camel_to_upper_snake("websocketServerLambdaName")
            == "WEBSOCKET_SERVER_LAMBDA_NAME"
        )

    def test_bucket_name(self):
        """Test simple two-word camelCase."""
        assert ghenv_lib.camel_to_upper_snake("bucketName") == "BUCKET_NAME"


class TestReadValuePairs:
    """Test cases for read_value_pairs function."""

    def test_txt_file_basic(self, tmp_path):
        """Test reading basic key=value pairs from a .txt file."""
        f = tmp_path / "test.txt"
        f.write_text("DB_HOST=localhost\nDB_PORT=5432\n")
        result = ghenv_lib.read_value_pairs(f)
        assert result == {"DB_HOST": "localhost", "DB_PORT": "5432"}

    def test_txt_file_with_comments(self, tmp_path):
        """Test that comments are ignored in .txt files."""
        f = tmp_path / "test.txt"
        f.write_text("DB_HOST=localhost\n# This is a comment\nDB_PORT=5432\n")
        result = ghenv_lib.read_value_pairs(f)
        assert result == {"DB_HOST": "localhost", "DB_PORT": "5432"}

    def test_txt_file_with_equals_in_value(self, tmp_path):
        """Test that only the first = is used to split."""
        f = tmp_path / "test.txt"
        f.write_text("CONNECTION=host=db;port=5432\n")
        result = ghenv_lib.read_value_pairs(f)
        assert result == {"CONNECTION": "host=db;port=5432"}

    def test_txt_file_empty_value_warns(self, tmp_path):
        """Test that empty values produce a warning when logger is provided."""
        f = tmp_path / "test.txt"
        f.write_text("DB_HOST=\n")
        logger = Mock()
        result = ghenv_lib.read_value_pairs(f, logger)
        assert result == {}
        logger.warning.assert_called_once()
        assert "empty value" in logger.warning.call_args[0][0]

    def test_txt_file_no_equals_warns(self, tmp_path):
        """Test that lines without = produce a warning when logger is provided."""
        f = tmp_path / "test.txt"
        f.write_text("DB_HOST\n")
        logger = Mock()
        result = ghenv_lib.read_value_pairs(f, logger)
        assert result == {}
        logger.warning.assert_called_once()
        assert "no '='" in logger.warning.call_args[0][0]

    def test_txt_file_no_logger_skips_silently(self, tmp_path):
        """Test that malformed lines are silently skipped without a logger."""
        f = tmp_path / "test.txt"
        f.write_text("DB_HOST\nDB_PORT=\nVALID=value\n")
        result = ghenv_lib.read_value_pairs(f)
        assert result == {"VALID": "value"}

    def test_txt_file_empty_lines(self, tmp_path):
        """Test that empty lines are skipped."""
        f = tmp_path / "test.txt"
        f.write_text("DB_HOST=localhost\n\n\nDB_PORT=5432\n")
        result = ghenv_lib.read_value_pairs(f)
        assert result == {"DB_HOST": "localhost", "DB_PORT": "5432"}

    def test_json_file_cdk_format(self, tmp_path):
        """Test reading AWS CDK output format JSON files."""
        f = tmp_path / "test.json"
        data = {"stack-name": {"apiServerName": "my-server", "bucketName": "my-bucket"}}
        f.write_text(json.dumps(data))
        result = ghenv_lib.read_value_pairs(f)
        assert result == {"API_SERVER_NAME": "my-server", "BUCKET_NAME": "my-bucket"}

    def test_json_file_non_dict_values_skipped(self, tmp_path):
        """Test that non-dict top-level values in JSON are skipped."""
        f = tmp_path / "test.json"
        data = {"stack-name": {"key": "value"}, "metadata": "not-a-dict"}
        f.write_text(json.dumps(data))
        result = ghenv_lib.read_value_pairs(f)
        assert result == {"KEY": "value"}

    def test_unsupported_format_raises(self, tmp_path):
        """Test that unsupported file formats raise ValueError."""
        f = tmp_path / "test.yaml"
        f.write_text("key: value")
        with pytest.raises(ValueError, match="Unsupported file format"):
            ghenv_lib.read_value_pairs(f)


# Integration test class
class TestIntegration:
    """Integration tests for the ghenv_lib module."""

    def test_full_workflow_with_mocks(self, requests_mock, tmp_path):
        """Test a complete workflow using mocked API calls."""
        # Setup test data
        test_dir = tmp_path / "data"
        test_dir.mkdir()

        # Create test files
        (test_dir / "app1.yml.vars").write_text("DB_HOST\nDB_PORT\n")
        (test_dir / "app1.yml.secs").write_text("DB_PASSWORD\nAPI_KEY\n")

        # Mock API responses
        # Public key fetch
        requests_mock.get(
            "https://api.github.com/repos/testowner/testrepo/environments/testenv/secrets/public-key",
            json={"key_id": "test_key", "key": "test_public_key"},
            status_code=200,
        )

        # Variable creation
        requests_mock.post(
            "https://api.github.com/repos/testowner/testrepo/environments/testenv/variables",
            status_code=201,
        )

        # Secret creation
        requests_mock.put(
            "https://api.github.com/repos/testowner/testrepo/environments/testenv/secrets/DB_PASSWORD",
            status_code=201,
        )
        requests_mock.put(
            "https://api.github.com/repos/testowner/testrepo/environments/testenv/secrets/API_KEY",
            status_code=201,
        )

        # Variable existence checks
        requests_mock.get(
            "https://api.github.com/repos/testowner/testrepo/environments/testenv/variables/DB_HOST",
            status_code=404,
        )
        requests_mock.get(
            "https://api.github.com/repos/testowner/testrepo/environments/testenv/variables/DB_PORT",
            status_code=404,
        )

        # Secret existence checks
        requests_mock.get(
            "https://api.github.com/repos/testowner/testrepo/environments/testenv/secrets/DB_PASSWORD",
            status_code=404,
        )
        requests_mock.get(
            "https://api.github.com/repos/testowner/testrepo/environments/testenv/secrets/API_KEY",
            status_code=404,
        )

        # Environment variables list
        requests_mock.get(
            "https://api.github.com/repos/testowner/testrepo/environments/testenv/variables?per_page=100&page=1",
            json={"variables": []},
            status_code=200,
        )

        # Environment secrets list
        requests_mock.get(
            "https://api.github.com/repos/testowner/testrepo/environments/testenv/secrets?per_page=100&page=1",
            json={"secrets": []},
            status_code=200,
        )

        # Test the workflow
        with patch.dict(os.environ, {"GH_API_SECRET": "test_token"}):
            logger = Mock()

            # Validate environment
            token, directory = ghenv_lib.validate_environment(str(test_dir), logger)
            assert token == "test_token"
            assert directory == test_dir

            # Find files
            var_files = ghenv_lib.find_files_by_extension(directory, "vars")
            sec_files = ghenv_lib.find_files_by_extension(directory, "secs")
            assert len(var_files) == 1
            assert len(sec_files) == 1

            # Read variable names
            var_names = ghenv_lib.read_variable_names(var_files)
            sec_names = ghenv_lib.read_variable_names(sec_files)
            assert var_names == ["DB_HOST", "DB_PORT"]
            assert sec_names == ["API_KEY", "DB_PASSWORD"]

            # Fetch public key
            key_id, public_key = ghenv_lib.fetch_public_key(
                "testowner", "testrepo", "testenv", token, logger
            )
            assert key_id == "test_key"
            assert public_key == "test_public_key"

            # Check variable existence
            assert not ghenv_lib.check_variable_exists(
                "testowner", "testrepo", "testenv", token, "DB_HOST"
            )

            # Check secret existence
            assert not ghenv_lib.check_secret_exists(
                "testowner", "testrepo", "testenv", token, "DB_PASSWORD"
            )

            # Get environment variables and secrets
            github_vars = ghenv_lib.get_environment_variables(
                "testowner", "testrepo", "testenv", token, logger
            )
            github_secs = ghenv_lib.get_environment_secrets(
                "testowner", "testrepo", "testenv", token, logger
            )
            assert github_vars == []
            assert github_secs == []


if __name__ == "__main__":
    # Run tests if script is executed directly
    pytest.main([__file__, "-v"])
