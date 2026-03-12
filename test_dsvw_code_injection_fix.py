#!/usr/bin/env python
"""
Comprehensive tests for Code Injection vulnerability remediation in dsvw.py

These tests verify that:
1. The dangerous exec() functionality has been removed
2. The include parameter no longer executes arbitrary code
3. File content is safely displayed without code execution
4. XSS is prevented through proper HTML escaping
5. The application doesn't crash with malicious payloads
"""

import unittest
import http.client
import threading
import time
import os
import tempfile
import sys
from unittest.mock import patch, MagicMock

# Import the application
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dsvw


class TestCodeInjectionRemediation(unittest.TestCase):
    """Test suite for Code Injection vulnerability fix"""

    @classmethod
    def setUpClass(cls):
        """Start the DSVW server in a background thread"""
        dsvw.init()
        cls.server = dsvw.ThreadingServer((dsvw.LISTEN_ADDRESS, dsvw.LISTEN_PORT), dsvw.ReqHandler)
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()
        time.sleep(0.5)  # Give server time to start

    @classmethod
    def tearDownClass(cls):
        """Shutdown the server"""
        cls.server.shutdown()

    def make_request(self, path):
        """Helper method to make HTTP requests to the test server"""
        try:
            conn = http.client.HTTPConnection(dsvw.LISTEN_ADDRESS, dsvw.LISTEN_PORT, timeout=5)
            conn.request("GET", path)
            response = conn.getresponse()
            status = response.status
            body = response.read().decode('utf-8', errors='replace')
            conn.close()
            return status, body
        except Exception as e:
            self.fail(f"Request failed: {e}")

    def test_no_code_execution_from_malicious_python_file(self):
        """
        Test that malicious Python code in an included file is NOT executed.

        This is the primary security test - we create a file with code that would
        have side effects if executed, and verify those side effects don't occur.
        """
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            # Write malicious Python code that would create a marker file if executed
            malicious_code = """
import os
# This should NOT be executed
marker_file = '/tmp/code_injection_test_marker_SHOULD_NOT_EXIST.txt'
with open(marker_file, 'w') as f:
    f.write('VULNERABLE - CODE WAS EXECUTED')
print('CODE EXECUTED - VULNERABLE!')
"""
            f.write(malicious_code)
            temp_file = f.name

        try:
            marker_file = '/tmp/code_injection_test_marker_SHOULD_NOT_EXIST.txt'

            # Ensure marker file doesn't exist before test
            if os.path.exists(marker_file):
                os.remove(marker_file)

            # Make request to include the malicious file
            status, body = self.make_request(f"/?include={temp_file}")

            # Verify the marker file was NOT created (code was not executed)
            self.assertFalse(
                os.path.exists(marker_file),
                "Marker file exists - malicious code was executed! Vulnerability still present."
            )

            # Verify we got a successful response
            self.assertEqual(status, 200, "Expected 200 OK response")

            # Verify the response contains the file content as text (not executed)
            self.assertIn('import os', body, "File content should be displayed as text")

            # Verify the dangerous print output is NOT in the response
            # (it would only be there if the code was executed)
            self.assertNotIn(
                'CODE EXECUTED - VULNERABLE!',
                body.replace('<pre>', '').replace('</pre>', '').replace('&lt;', '<').replace('&gt;', '>'),
                "Code execution output detected - vulnerability still present!"
            )

        finally:
            # Cleanup
            if os.path.exists(temp_file):
                os.remove(temp_file)
            if os.path.exists(marker_file):
                os.remove(marker_file)

    def test_no_system_command_execution(self):
        """
        Test that system commands embedded in included files are not executed.
        """
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            # Code that would execute system commands if executed
            malicious_code = """
import subprocess
result = subprocess.check_output(['echo', 'SYSTEM_COMMAND_EXECUTED'])
print(result.decode())
"""
            f.write(malicious_code)
            temp_file = f.name

        try:
            status, body = self.make_request(f"/?include={temp_file}")

            # Verify the subprocess code is shown as text, not executed
            self.assertIn('import subprocess', body, "File content should be displayed")
            self.assertNotIn(
                'SYSTEM_COMMAND_EXECUTED',
                body.replace('&lt;', '<').replace('&gt;', '>'),
                "System command was executed - vulnerability still present!"
            )

        finally:
            if os.path.exists(temp_file):
                os.remove(temp_file)

    def test_no_environment_variable_access(self):
        """
        Test that included code cannot access environment variables or server context.

        The old vulnerable code passed envs dict with server info to exec().
        Verify this information is no longer accessible to included files.
        """
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            # Code that would access the envs dictionary if executed
            malicious_code = """
# The old vulnerable code provided these in envs dict
print(f"DOCUMENT_ROOT: {DOCUMENT_ROOT}")
print(f"HTTP_USER_AGENT: {HTTP_USER_AGENT}")
print(f"REMOTE_ADDR: {REMOTE_ADDR}")
"""
            f.write(malicious_code)
            temp_file = f.name

        try:
            status, body = self.make_request(f"/?include={temp_file}")

            # The file content should be displayed, but not executed
            self.assertIn('DOCUMENT_ROOT', body, "File content should be visible")

            # Verify actual environment values are NOT in the output
            # (they would only appear if code was executed with envs context)
            self.assertNotIn('127.0.0.1', body.replace('REMOTE_ADDR', ''))

        finally:
            if os.path.exists(temp_file):
                os.remove(temp_file)

    def test_html_escaping_prevents_xss(self):
        """
        Test that file content containing HTML/JavaScript is properly escaped.

        This prevents a secondary XSS vulnerability that could arise from
        displaying file content without escaping.
        """
        with tempfile.NamedTemporaryFile(mode='w', suffix='.html', delete=False) as f:
            # Malicious content with XSS payload
            xss_payload = '<script>alert("XSS")</script><img src=x onerror="alert(1)">'
            f.write(xss_payload)
            temp_file = f.name

        try:
            status, body = self.make_request(f"/?include={temp_file}")

            # Verify HTML is escaped (< becomes &lt;, > becomes &gt;)
            self.assertIn('&lt;script&gt;', body, "Script tags should be HTML-escaped")
            self.assertIn('&lt;img', body, "HTML tags should be escaped")

            # Verify raw dangerous HTML is NOT present
            self.assertNotIn('<script>alert', body, "Raw script tag found - XSS vulnerability!")
            self.assertNotIn('<img src=x onerror=', body, "Raw img tag found - XSS vulnerability!")

        finally:
            if os.path.exists(temp_file):
                os.remove(temp_file)

    def test_include_parameter_with_normal_text_file(self):
        """
        Test that legitimate use case (displaying text file) still works.

        Verify the fix doesn't break valid functionality.
        """
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            test_content = "This is a normal text file.\nLine 2\nLine 3"
            f.write(test_content)
            temp_file = f.name

        try:
            status, body = self.make_request(f"/?include={temp_file}")

            self.assertEqual(status, 200, "Should successfully handle normal text files")
            self.assertIn('This is a normal text file', body, "File content should be displayed")
            self.assertIn('Line 2', body, "Multi-line content should be preserved")

        finally:
            if os.path.exists(temp_file):
                os.remove(temp_file)

    def test_no_exec_function_in_code(self):
        """
        Static code analysis test: Verify exec() is not used in the include handler.

        This is a defense-in-depth check to ensure the dangerous function is removed.
        """
        with open('dsvw.py', 'r') as f:
            content = f.read()

        # Find the include parameter handling section
        lines = content.split('\n')
        include_section = []
        in_include_block = False

        for i, line in enumerate(lines):
            if '"include" in params' in line:
                in_include_block = True
            if in_include_block:
                include_section.append(line)
                if 'elif' in line and i > 0 and '"include"' not in line:
                    break
                if line.strip().startswith('elif ') and '"include"' not in line:
                    break

        include_code = '\n'.join(include_section)

        # Verify exec() is not used in the include handler
        self.assertNotIn('exec(', include_code,
                        "exec() function found in include handler - vulnerability not fixed!")

    def test_stdout_not_redirected(self):
        """
        Test that sys.stdout is not manipulated in the include handler.

        The old vulnerable code redirected stdout to capture exec() output.
        Verify this is no longer happening.
        """
        with open('dsvw.py', 'r') as f:
            content = f.read()

        lines = content.split('\n')
        include_section = []
        in_include_block = False

        for i, line in enumerate(lines):
            if '"include" in params' in line:
                in_include_block = True
            if in_include_block:
                include_section.append(line)
                if line.strip().startswith('elif ') and '"include"' not in line:
                    break

        include_code = '\n'.join(include_section)

        # Verify sys.stdout manipulation is removed
        self.assertNotIn('sys.stdout', include_code,
                        "sys.stdout manipulation found - code execution pattern still present!")
        self.assertNotIn('io.StringIO()', include_code,
                        "StringIO usage found - output capture pattern still present!")

    def test_malicious_file_with_global_modifications(self):
        """
        Test that included code cannot modify global state or variables.
        """
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            # Code that would modify global state if executed
            malicious_code = """
# Attempt to modify global application state
import dsvw
dsvw.LISTEN_PORT = 99999
CONNECTION = None
print("GLOBALS MODIFIED")
"""
            f.write(malicious_code)
            temp_file = f.name

        try:
            original_port = dsvw.LISTEN_PORT
            status, body = self.make_request(f"/?include={temp_file}")

            # Verify global state was not modified
            self.assertEqual(dsvw.LISTEN_PORT, original_port,
                           "Global variable was modified - code was executed!")
            self.assertNotIn('GLOBALS MODIFIED', body,
                           "Global modification code was executed!")

        finally:
            if os.path.exists(temp_file):
                os.remove(temp_file)

    def test_response_contains_pre_tag(self):
        """
        Test that the response uses <pre> tag for proper formatting.

        This ensures the fix displays content in a readable, safe way.
        """
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("Test content")
            temp_file = f.name

        try:
            status, body = self.make_request(f"/?include={temp_file}")

            # Verify content is wrapped in <pre> tags for safe display
            self.assertIn('<pre>', body, "Content should be in <pre> tag")
            self.assertIn('</pre>', body, "Content should be in <pre> tag")

        finally:
            if os.path.exists(temp_file):
                os.remove(temp_file)

    def test_error_handling_for_nonexistent_file(self):
        """
        Test that requesting a non-existent file is handled gracefully.
        """
        status, body = self.make_request("/?include=/nonexistent/file/path/test.txt")

        # Should return an error (either 500 or error message)
        # The important thing is it doesn't try to execute non-existent code
        self.assertIn(str(status), ['500', '200'])  # May return 500 or caught exception


class TestRegressionPrevention(unittest.TestCase):
    """
    Tests to ensure the vulnerability cannot be reintroduced through common mistakes.
    """

    def test_no_eval_in_include_handler(self):
        """Ensure eval() is also not used (similar dangerous function)"""
        with open('dsvw.py', 'r') as f:
            content = f.read()

        # Get include section
        if '"include" in params' in content:
            start = content.find('"include" in params')
            end = content.find('elif ', start + 1)
            if end == -1:
                end = content.find('if HTML_PREFIX', start)
            include_section = content[start:end]

            self.assertNotIn('eval(', include_section,
                           "eval() found - similar vulnerability present!")

    def test_no_compile_exec_pattern(self):
        """Ensure compile() + exec() pattern is not used"""
        with open('dsvw.py', 'r') as f:
            content = f.read()

        if '"include" in params' in content:
            start = content.find('"include" in params')
            end = content.find('elif ', start + 1)
            if end == -1:
                end = content.find('if HTML_PREFIX', start)
            include_section = content[start:end]

            self.assertNotIn('compile(', include_section,
                           "compile() found - code compilation pattern present!")

    def test_html_escape_is_used(self):
        """Verify html.escape() is used to prevent XSS"""
        with open('dsvw.py', 'r') as f:
            content = f.read()

        if '"include" in params' in content:
            start = content.find('"include" in params')
            end = content.find('elif ', start + 1)
            if end == -1:
                end = content.find('if HTML_PREFIX', start)
            include_section = content[start:end]

            self.assertIn('html.escape', include_section,
                         "html.escape() not found - XSS vulnerability may exist!")


if __name__ == '__main__':
    # Run tests with verbose output
    unittest.main(verbosity=2)
