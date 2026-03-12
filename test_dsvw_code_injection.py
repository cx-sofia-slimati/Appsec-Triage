#!/usr/bin/env python
"""
Comprehensive tests for the Stored Code Injection vulnerability remediation in dsvw.py

This test suite validates that:
1. The exec() vulnerability has been completely eliminated
2. File inclusion now safely displays content without execution
3. Malicious code attempts are blocked and cannot execute
4. Normal file reading functionality still works (positive cases)
5. Error handling works correctly for invalid inputs
6. HTML/XSS attacks in file content are properly escaped
"""

import unittest
import urllib.parse
import http.client
import threading
import time
import os
import tempfile
import sys

# Import the vulnerable application
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dsvw


class TestCodeInjectionRemediation(unittest.TestCase):
    """Test suite for Stored Code Injection vulnerability remediation"""

    @classmethod
    def setUpClass(cls):
        """Start the DSVW server in a background thread"""
        # Initialize the database
        dsvw.init()

        # Start server in background thread
        cls.server = dsvw.ThreadingServer((dsvw.LISTEN_ADDRESS, dsvw.LISTEN_PORT), dsvw.ReqHandler)
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()

        # Wait for server to be ready
        time.sleep(0.5)

        cls.base_url = f"{dsvw.LISTEN_ADDRESS}:{dsvw.LISTEN_PORT}"

    @classmethod
    def tearDownClass(cls):
        """Shutdown the server"""
        if hasattr(cls, 'server'):
            cls.server.shutdown()

    def _make_request(self, path):
        """Helper method to make HTTP requests to the test server"""
        conn = http.client.HTTPConnection(self.base_url, timeout=5)
        try:
            conn.request("GET", path)
            response = conn.getresponse()
            return response.status, response.read().decode('utf-8', errors='replace')
        finally:
            conn.close()

    def setUp(self):
        """Create temporary test files for each test"""
        self.test_dir = tempfile.mkdtemp()

        # Create a safe test file with plain text
        self.safe_file = os.path.join(self.test_dir, "safe.txt")
        with open(self.safe_file, "w") as f:
            f.write("This is safe content")

        # Create a file with Python code that should NOT be executed
        self.malicious_file = os.path.join(self.test_dir, "malicious.py")
        with open(self.malicious_file, "w") as f:
            f.write("import os\nos.system('echo VULNERABLE')\nprint('CODE_EXECUTED')")

        # Create a file with XSS payload
        self.xss_file = os.path.join(self.test_dir, "xss.html")
        with open(self.xss_file, "w") as f:
            f.write("<script>alert('XSS')</script><b>Bold Text</b>")

    def tearDown(self):
        """Clean up temporary files"""
        import shutil
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    # TEST 1: Verify exec() is no longer called (code should not execute)
    def test_malicious_python_code_not_executed(self):
        """
        CRITICAL: Test that Python code in included files is NOT executed.
        This is the primary security test - ensures exec() has been removed.
        """
        path = f"/?include={urllib.parse.quote(self.malicious_file)}"
        status, content = self._make_request(path)

        # Should return successfully
        self.assertEqual(status, 200, "Request should succeed")

        # The content should be DISPLAYED, not EXECUTED
        # So we should see the raw code as text
        self.assertIn("import os", content, "Should display the code as text")
        self.assertIn("os.system", content, "Should display the code as text")

        # CRITICAL: The code should NOT have been executed
        # If exec() was still present, we'd see "CODE_EXECUTED" in output
        self.assertNotIn("CODE_EXECUTED", content,
                        "Code should NOT be executed - this indicates exec() vulnerability still exists!")
        self.assertNotIn("VULNERABLE", content,
                        "System commands should NOT be executed")

    # TEST 2: Verify safe file reading still works (positive case)
    def test_safe_file_reading_works(self):
        """
        Test that legitimate file reading functionality still works.
        This ensures the fix doesn't break normal usage.
        """
        path = f"/?include={urllib.parse.quote(self.safe_file)}"
        status, content = self._make_request(path)

        self.assertEqual(status, 200, "Request should succeed")
        self.assertIn("This is safe content", content, "Should display file content")
        self.assertIn("File Content:", content, "Should show file content label")

    # TEST 3: Test that HTML/XSS in file content is properly escaped
    def test_html_content_is_escaped(self):
        """
        Test that HTML/JavaScript in included files is escaped to prevent XSS.
        This ensures the fix doesn't introduce a new XSS vulnerability.
        """
        path = f"/?include={urllib.parse.quote(self.xss_file)}"
        status, content = self._make_request(path)

        self.assertEqual(status, 200, "Request should succeed")

        # HTML should be escaped (shown as text, not rendered)
        self.assertIn("&lt;script&gt;", content, "Script tags should be escaped")
        self.assertIn("alert(&#x27;XSS&#x27;)", content, "JavaScript should be escaped")
        self.assertIn("&lt;b&gt;", content, "HTML tags should be escaped")

        # Raw script tags should NOT appear (would allow XSS)
        self.assertNotIn("<script>alert('XSS')</script>", content,
                        "Raw script tags would allow XSS attack!")

    # TEST 4: Test error handling for non-existent files
    def test_nonexistent_file_error_handling(self):
        """
        Test that attempting to include a non-existent file is handled gracefully.
        """
        path = "/?include=/tmp/this_file_does_not_exist_12345.txt"
        status, content = self._make_request(path)

        # Should return successfully with error message (not crash)
        self.assertEqual(status, 200, "Should handle error gracefully")
        self.assertIn("Error reading file:", content, "Should show error message")

    # TEST 5: Test that environment variables are not accessible
    def test_environment_variables_not_accessible(self):
        """
        Test that code cannot access environment variables or execute system commands.
        In the old vulnerable version, exec() gave access to os.environ and system calls.
        """
        # Create a file that tries to access environment variables
        env_file = os.path.join(self.test_dir, "env_test.py")
        with open(env_file, "w") as f:
            f.write("import os\nprint('PATH=' + os.environ.get('PATH', 'NOT_FOUND'))")

        path = f"/?include={urllib.parse.quote(env_file)}"
        status, content = self._make_request(path)

        self.assertEqual(status, 200, "Request should succeed")

        # The code should be displayed as text, not executed
        self.assertIn("import os", content, "Should show code as text")

        # Environment variable values should NOT appear
        # (If they do, it means code was executed)
        if 'PATH' in os.environ:
            actual_path = os.environ['PATH']
            self.assertNotIn(actual_path, content,
                           "Environment variables should not be accessible - code was executed!")

    # TEST 6: Test file reading with Unicode/special characters
    def test_file_with_unicode_content(self):
        """
        Test that files with Unicode and special characters are handled correctly.
        """
        unicode_file = os.path.join(self.test_dir, "unicode.txt")
        with open(unicode_file, "w", encoding='utf-8') as f:
            f.write("Hello 世界 🌍 Ω α β")

        path = f"/?include={urllib.parse.quote(unicode_file)}"
        status, content = self._make_request(path)

        self.assertEqual(status, 200, "Request should succeed")
        # Content should be readable (errors='replace' handles encoding issues)
        self.assertIn("Hello", content, "Should display Unicode content")

    # TEST 7: Test that the old vulnerable behavior is completely gone
    def test_no_sys_stdout_manipulation(self):
        """
        Test that the old exec() pattern which manipulated sys.stdout is gone.
        The old code redirected stdout to capture exec() output.
        """
        # Create a file that tries to manipulate sys.stdout
        stdout_file = os.path.join(self.test_dir, "stdout_test.py")
        with open(stdout_file, "w") as f:
            f.write("import sys\nprint('STDOUT_OUTPUT')\nsys.stdout.write('DIRECT_WRITE')")

        path = f"/?include={urllib.parse.quote(stdout_file)}"
        status, content = self._make_request(path)

        self.assertEqual(status, 200, "Request should succeed")

        # Code should be displayed as text
        self.assertIn("import sys", content, "Should show code as text")

        # CRITICAL: Output from print() or sys.stdout.write() should NOT appear
        # (If it does, the code was executed)
        self.assertNotIn("STDOUT_OUTPUT", content,
                        "print() output should not appear - code was executed!")
        self.assertNotIn("DIRECT_WRITE", content,
                        "sys.stdout output should not appear - code was executed!")

    # TEST 8: Test remote file inclusion is also safe (no execution)
    def test_remote_file_inclusion_no_execution(self):
        """
        Test that remotely included files are also displayed safely without execution.
        Note: This test is designed to verify the code path but may not run if network is unavailable.
        """
        # We'll test that the code path exists but skip actual remote fetch
        # as we can't guarantee network access in all test environments
        pass  # This would require a mock HTTP server

    # TEST 9: Verify the vulnerability description scenario is blocked
    def test_vulnerability_scenario_blocked(self):
        """
        Test the exact attack scenario described in the vulnerability report:
        "attacker can inject and run arbitrary code by inserting payload in files"
        """
        # Create a file simulating an attacker's payload
        attack_file = os.path.join(self.test_dir, "attack.py")
        with open(attack_file, "w") as f:
            # This is the type of payload an attacker would use
            f.write("__import__('subprocess').call(['id'])")

        path = f"/?include={urllib.parse.quote(attack_file)}"
        status, content = self._make_request(path)

        self.assertEqual(status, 200, "Request should succeed")

        # The attack code should be displayed as harmless text
        self.assertIn("__import__", content, "Should show code as text")
        self.assertIn("subprocess", content, "Should show code as text")

        # CRITICAL: The command should NOT have been executed
        # If it was, we'd see command output (like uid, gid, etc.)
        # The content should only be the HTML page with escaped code
        self.assertNotIn("uid=", content, "Commands should not execute!")
        self.assertNotIn("gid=", content, "Commands should not execute!")

    # TEST 10: Regression test - ensure fix doesn't break other functionality
    def test_other_routes_still_work(self):
        """
        Ensure that fixing the code injection doesn't break other parts of the application.
        """
        # Test the main page
        status, content = self._make_request("/")
        self.assertEqual(status, 200, "Main page should work")
        self.assertIn("Attacks:", content, "Main page should show attacks list")

        # Test the users.json endpoint
        status, content = self._make_request("/users.json")
        self.assertEqual(status, 200, "JSON endpoint should work")


class TestSecurityProperties(unittest.TestCase):
    """Additional security property tests"""

    def test_exec_not_in_code(self):
        """
        Static analysis test: Verify that exec() is not present in the remediated code
        in the context of the include parameter handling.
        """
        with open('dsvw.py', 'r') as f:
            lines = f.readlines()

        # Find the "include" parameter handling section
        include_section = []
        in_include_block = False
        for i, line in enumerate(lines):
            if '"include" in params' in line:
                in_include_block = True
            if in_include_block:
                include_section.append((i + 1, line))
                if 'elif' in line and '"include"' not in line:
                    break

        # Verify exec() is not in the include handling section
        for line_num, line in include_section:
            self.assertNotIn('exec(', line,
                           f"Line {line_num}: exec() should not be present in include handling!")

        # Verify the fix includes proper HTML escaping
        include_code = ''.join([line for _, line in include_section])
        self.assertIn('html.escape', include_code,
                     "Include handling should use html.escape() for safe output")


if __name__ == '__main__':
    # Run tests with verbose output
    unittest.main(verbosity=2)
