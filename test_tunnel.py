"""
Test script to verify Cloudflare Tunnel connectivity with local Flask server.
Starts host_server.py briefly, captures the trycloudflare.com URL,
performs an HTTPS GET request to verify end-to-end routing, and exits.
"""

import subprocess
import time
import re
import urllib.request
import sys
import os

PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))

def test_tunnel():
    print("[*] Launching host_server.py in subprocess for tunnel verification...")
    proc = subprocess.Popen(
        [sys.executable, '-u', os.path.join(PROJECT_DIR, 'host_server.py')],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding='utf-8',
        errors='ignore'
    )

    url_pattern = re.compile(r'https://[a-zA-Z0-9-]+\.trycloudflare\.com')
    public_url = None

    start_time = time.time()
    try:
        while time.time() - start_time < 30:
            line = proc.stdout.readline()
            if line:
                print("  [OUT]", line.strip())
                match = url_pattern.search(line)
                if match:
                    public_url = match.group(0)
                    print(f"\n[+] DETECTED PUBLIC HTTPS URL: {public_url}")
                    break
            time.sleep(0.1)

        assert public_url is not None, "Failed to capture public HTTPS tunnel URL within 30 seconds"

        # Give Cloudflare a moment to propagate routing
        time.sleep(3)

        print(f"[*] Making HTTPS GET request to: {public_url}/dashboard ...")
        req = urllib.request.Request(
            f"{public_url}/dashboard",
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) REALSAFE-Test-Agent'}
        )
        with urllib.request.urlopen(req, timeout=15) as response:
            status = response.status
            content = response.read().decode('utf-8')
            print(f"[+] Response status: {status}")
            assert status == 200, f"Expected 200, got {status}"
            assert "REALSAFE" in content, "REALSAFE brand string not found in response HTML"
            print("[+] Successfully fetched REALSAFE dashboard over public Cloudflare HTTPS tunnel!")

        print("\n=======================================================")
        print("CLOUDFLARE TUNNEL HOST VERIFICATION PASSED (100% OK)!")
        print("=======================================================")

    finally:
        print("[*] Terminating test host server process...")
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()

if __name__ == '__main__':
    test_tunnel()
