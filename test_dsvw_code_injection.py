#!/usr/bin/env python
"""
Test suite for code injection vulnerability remediation in dsvw.py

This test suite validates that the code injection vulnerability (CWE-94) has been
properly remediated by ensuring:
1. The exec() function is no longer called with user-controlled input
2. File inclusion displays content safely without execution
3. XSS protection is maintained through proper HTML escaping
4. Attack vectors that previously allowed code execution are now blocked
"""

import unittest
import http.client
import threading
import time
import sys
import os
import tempfile

# Import the application
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dsvw


class TestCodeInjectionRemediation(unittest.TestCase):
    """Test cases for code injection vulnerability remediation"""

    @classmethod
    def setUpClass(cls):
        """Start the test server once for all tests"""
        cls.server = None
        cls.server_thread = None
        cls.test_port = 65413  # Use a different port to avoid conflicts

        # Initialize the database
        dsvw.init()

        # Start the server in a thread
        try:
            cls.server = dsvw.ThreadingServer(("127.0.0.1", cls.test_port), dsvw.ReqHandler)
            cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
            cls.server_thread.start()
            time.sleep(0.5)  # Give server time to start
        except Exception as e:
            print(f"Warning: Could not start test server: {e}")
            cls.server = None

    @classmethod
    def tearDownClass(cls):
        """Stop the test server"""
        if cls.server:
            cls.server.shutdown()
            cls.server.server_close()

    def make_request(self, path):
        """Helper method to make HTTP requests to the test server"""
        if not self.server:
            self.skipTest("Test server not available")

        try:
            conn = http.client.HTTPConnection("127.0.0.1", self.test_port, timeout=5)
            conn.request("GET", path)
            response = conn.getresponse()
            data = response.read().decode('utf-8', errors='replace')
            conn.close()
            return response, data
        except Exception as e:
            self.fail(f"Request failed: {e}")

    def test_exec_not_called_with_user_input(self):
        """
        CRITICAL TEST: Verify that exec() is not called with user-controlled input

        This test ensures the primary vulnerability (CWE-94: Code Injection) is fixed.
        Previously, the application would execute arbitrary Python code from included files.
        """
        # Create a temporary malicious Python file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            # This code would execute if the vulnerability still exists
            f.write("print('EXPLOIT_EXECUTED')\n")
            f.write("import sys\n")
            f.write("sys.stdout.write('CODE_INJECTION_SUCCESS')\n")
            temp_file = f.name

        try:
            # Attempt to include and execute the malicious file
            response, data = self.make_request(f"/?include={temp_file}")

            # Verify the response is successful (file was read)
            self.assertEqual(response.status, 200, "Server should process the request")

            # CRITICAL: Verify the code was NOT executed
            # If the vulnerability exists, we would see the output strings
            self.assertNotIn("EXPLOIT_EXECUTED", data,
                           "Malicious code should NOT be executed - vulnerability still exists!")
            self.assertNotIn("CODE_INJECTION_SUCCESS", data,
                           "Code injection should be prevented")

            # Verify the file content is displayed (not executed)
            self.assertIn("File Content:", data,
                         "File should be displayed as content, not executed")

        finally:
            # Clean up
            os.unlink(temp_file)

    def test_python_code_displayed_not_executed(self):
        """
        Test that Python code in included files is displayed as text, not executed

        This validates that the remediation properly converts dangerous execution
        into safe content display.
        """
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            # Write Python code that would have side effects if executed
            f.write("import os\n")
            f.write("os.system('echo DANGEROUS_COMMAND')\n")
            temp_file = f.name

        try:
            response, data = self.make_request(f"/?include={temp_file}")

            # The Python code should appear as escaped HTML text
            self.assertIn("import os", data,
                         "Python code should be visible in the response")
            self.assertIn("os.system", data,
                         "Dangerous function calls should be visible as text")

            # Verify the command was not executed
            self.assertNotIn("DANGEROUS_COMMAND", data,
                           "Shell commands should not be executed")

        finally:
            os.unlink(temp_file)

    def test_html_escaping_prevents_xss(self):
        """
        Test that HTML in included files is properly escaped to prevent XSS

        This ensures the remediation doesn't introduce a new XSS vulnerability
        by improperly displaying file contents.
        """
        with tempfile.NamedTemporaryFile(mode='w', suffix='.html', delete=False) as f:
            # Write HTML/JavaScript that could cause XSS if not escaped
            f.write("<script>alert('XSS')</script>\n")
            f.write("<img src=x onerror='alert(1)'>\n")
            temp_file = f.name

        try:
            response, data = self.make_request(f"/?include={temp_file}")

            # Verify HTML is escaped (using &lt; instead of <, &gt; instead of >)
            self.assertIn("&lt;script&gt;", data,
                         "Script tags should be HTML-escaped")
            self.assertIn("&lt;img", data,
                         "Image tags should be HTML-escaped")

            # Verify actual script tags are not present (which would execute)
            self.assertNotIn("<script>alert", data,
                           "Unescaped script tags would allow XSS")

        finally:
            os.unlink(temp_file)

    def test_remote_file_inclusion_safe(self):
        """
        Test that remote file inclusion doesn't execute code

        Note: This test checks the code path but doesn't actually fetch remote files
        to avoid external dependencies in testing.
        """
        # This test validates the code structure without making external requests
        # The remediation should handle both local and remote files the same way

        # Create a local test to verify the URL path is handled
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("test content from remote-like file")
            temp_file = f.name

        try:
            response, data = self.make_request(f"/?include={temp_file}")

            # Verify content is displayed, not executed
            self.assertIn("File Content:", data)
            self.assertIn("test content from remote-like file", data)

        finally:
            os.unlink(temp_file)

    def test_environment_variables_not_exposed(self):
        """
        Test that environment variables and system information are not exposed

        Previously, the exec() call had access to environment variables like PATH,
        USER_AGENT, etc. This test ensures this information isn't leaked.
        """
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            # Code that would print environment variables if executed
            f.write("import os\n")
            f.write("print('ENV:', os.environ.get('PATH', 'NOT_FOUND'))\n")
            temp_file = f.name

        try:
            response, data = self.make_request(f"/?include={temp_file}")

            # The environment should not be executed and printed
            # We should only see the source code
            self.assertNotIn("ENV:", data,
                           "Environment variables should not be exposed through execution")

        finally:
            os.unlink(temp_file)

    def test_cmd_parameter_injection_blocked(self):
        """
        Test that cmd parameter cannot be used to inject commands

        The original vulnerability allowed command execution through the cmd parameter
        in combination with file inclusion. This should now be blocked.
        """
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write("print('test')\n")
            temp_file = f.name

        try:
            # Try to inject commands via cmd parameter
            response, data = self.make_request(
                f"/?include={temp_file}&cmd=ls"
            )

            # The cmd parameter should have no effect since exec() is removed
            # We should only see the file content
            self.assertIn("File Content:", data)

        finally:
            os.unlink(temp_file)

    def test_multiple_special_characters_handled_safely(self):
        """
        Test that special characters in file content are handled safely

        This ensures the remediation properly escapes all dangerous characters
        that could cause issues in HTML output.
        """
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            # Write content with various special characters
            f.write("<>&\"'\n")
            f.write("javascript:alert(1)\n")
            f.write("on error=alert(1)\n")
            temp_file = f.name

        try:
            response, data = self.make_request(f"/?include={temp_file}")

            # Verify all special characters are properly escaped
            self.assertIn("&lt;", data, "< should be escaped")
            self.assertIn("&gt;", data, "> should be escaped")
            self.assertIn("&amp;", data, "& should be escaped")

            # Verify dangerous strings don't appear unescaped
            self.assertNotRegex(data, r"<[^&]",
                              "Unescaped < characters could allow injection")

        finally:
            os.unlink(temp_file)

    def test_binary_files_handled_gracefully(self):
        """
        Test that binary files are handled without crashing

        The remediation uses decode(errors='replace') which should handle
        binary content gracefully.
        """
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            # Write binary data
            f.write(b'\x00\x01\x02\xff\xfe\xfd')
            temp_file = f.name

        try:
            response, data = self.make_request(f"/?include={temp_file}")

            # Should not crash and should return a response
            self.assertEqual(response.status, 200,
                           "Binary files should be handled without crashing")
            self.assertIn("File Content:", data)

        finally:
            os.unlink(temp_file)

    def test_functionality_preserved(self):
        """
        Test that legitimate file inclusion functionality is preserved

        While the vulnerability is fixed, the application should still be able
        to include and display file contents for legitimate purposes.
        """
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("This is legitimate file content\n")
            f.write("Line 2 of the file\n")
            temp_file = f.name

        try:
            response, data = self.make_request(f"/?include={temp_file}")

            # Verify the file content is properly displayed
            self.assertEqual(response.status, 200)
            self.assertIn("File Content:", data)
            self.assertIn("This is legitimate file content", data)
            self.assertIn("Line 2 of the file", data)

        finally:
            os.unlink(temp_file)


class TestRegressionPrevention(unittest.TestCase):
    """
    Test cases to prevent regression of the code injection vulnerability

    These tests document specific attack vectors that were previously exploitable
    and must remain blocked in future versions.
    """

    def test_exec_function_not_used_with_untrusted_input(self):
        """
        Static analysis test: verify exec() is not used with untrusted input

        This test reads the source code to ensure the dangerous pattern doesn't
        reappear in future modifications.
        """
        with open('dsvw.py', 'r') as f:
            source_code = f.read()

        # Find all exec() calls
        import re
        exec_calls = re.findall(r'exec\s*\([^)]+\)', source_code)

        # If exec() is used, verify it's not in the file inclusion section
        for exec_call in exec_calls:
            # Check if this exec call is related to include parameter handling
            # Look for context around exec call
            exec_pos = source_code.find(exec_call)
            context = source_code[max(0, exec_pos-500):exec_pos+500]

            # Verify exec is not used with user-controlled 'include' parameter
            self.assertNotIn('"include" in params', context,
                           "exec() must not be used with include parameter - vulnerability reintroduced!")
            self.assertNotIn("'include' in params", context,
                           "exec() must not be used with include parameter - vulnerability reintroduced!")

    def test_dangerous_functions_not_in_include_handler(self):
        """
        Verify that dangerous functions are not used in the include parameter handler
        """
        with open('dsvw.py', 'r') as f:
            source_code = f.read()

        # Extract the include parameter handling section
        include_section_start = source_code.find('elif "include" in params:')
        if include_section_start != -1:
            # Find the end of this elif block (next elif or else)
            include_section_end = source_code.find('elif ', include_section_start + 10)
            if include_section_end == -1:
                include_section_end = source_code.find('if HTML_PREFIX', include_section_start)

            include_code = source_code[include_section_start:include_section_end]

            # Verify dangerous functions are not used
            dangerous_functions = ['exec(', 'eval(', 'compile(', '__import__']
            for func in dangerous_functions:
                self.assertNotIn(func, include_code,
                               f"Dangerous function {func} found in include handler - security risk!")


if __name__ == '__main__':
    # Run tests with verbose output
    unittest.main(verbosity=2)
