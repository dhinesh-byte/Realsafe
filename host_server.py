"""
REALSAFE — Automated Laptop Host & Cloudflare HTTPS Tunnel Orchestrator
Starts the local Flask web server and establishes a secure Cloudflare Tunnel,
extracting and displaying the public HTTPS URL for instant sharing with friends.
"""

import sys
import os
import subprocess
import threading
import time
import re
import signal

# Ensure Windows consoles handle UTF-8 cleanly without crashing on encodings
if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

# Ensure current directory is in Python path
PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_DIR)

from app import app
from models.database import init_db

HOST = os.environ.get('HOST', '0.0.0.0')
PORT = int(os.environ.get('PORT', 5000))

def find_cloudflared_binary():
    """Locates the cloudflared executable in the local folder, parent folder, or PATH."""
    candidates = [
        os.path.join(PROJECT_DIR, 'cloudflared.exe'),
        os.path.join(os.path.dirname(PROJECT_DIR), 'cloudflared.exe'),
        'cloudflared.exe',
        'cloudflared'
    ]
    for c in candidates:
        if os.path.exists(c):
            return os.path.abspath(c)
    # Check PATH
    import shutil
    path_bin = shutil.which('cloudflared')
    if path_bin:
        return path_bin
    return None

def run_flask():
    """Starts the Flask server with debug=False on 0.0.0.0."""
    try:
        init_db()
        # Run Flask server quietly without debug reloader to prevent duplicate processes
        app.run(host=HOST, port=PORT, debug=False, use_reloader=False, threaded=True)
    except Exception as e:
        print(f"[ERROR] Flask server failed to start: {e}", file=sys.stderr, flush=True)

def main():
    print("========================================================================", flush=True)
    print("  [REALSAFE] HOST SERVER -- INITIALIZING", flush=True)
    print("========================================================================", flush=True)
    print(f"[*] Starting local Flask server on {HOST}:{PORT} (debug=False)...", flush=True)

    # 1. Start Flask in background thread
    flask_thread = threading.Thread(target=run_flask, daemon=True)
    flask_thread.start()
    time.sleep(1.5) # Give Flask a moment to bind the socket

    # 2. Locate cloudflared binary
    cloudflared_path = find_cloudflared_binary()
    if not cloudflared_path:
        print("\n[!] Could not locate 'cloudflared.exe'.", flush=True)
        print("    Please ensure cloudflared.exe is placed in the project folder or installed in PATH.", flush=True)
        print(f"    Local server is still accessible on: http://localhost:{PORT}", flush=True)
        print("========================================================================", flush=True)
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[REALSAFE] Server stopped.", flush=True)
            return

    print(f"[*] Found Cloudflare Tunnel binary: {cloudflared_path}", flush=True)
    print(f"[*] Establishing secure Cloudflare Tunnel to http://127.0.0.1:{PORT}...", flush=True)

    # 3. Launch cloudflared tunnel
    cmd = [
        cloudflared_path,
        'tunnel',
        '--url', f'http://127.0.0.1:{PORT}'
    ]

    try:
        # cloudflared logs tunnel output to stderr
        tunnel_proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding='utf-8',
            errors='ignore',
            bufsize=1
        )
    except Exception as e:
        print(f"[!] Failed to launch cloudflared: {e}", flush=True)
        return

    public_url = None
    url_pattern = re.compile(r'https://[a-zA-Z0-9-]+\.trycloudflare\.com')

    # Monitor tunnel output for the public HTTPS URL
    def monitor_stream(stream):
        nonlocal public_url
        for line in stream:
            match = url_pattern.search(line)
            if match and not public_url:
                public_url = match.group(0)
                print("\n========================================================================", flush=True)
                print("  >>> REALSAFE SECURE HOST SERVER IS LIVE! <<<", flush=True)
                print("========================================================================", flush=True)
                print(f"  [PUBLIC HTTPS SHARE LINK]:", flush=True)
                print(f"     >>> {public_url} <<<", flush=True)
                print("", flush=True)
                print(f"  [LOCAL ACCESS ON THIS LAPTOP]:", flush=True)
                print(f"     http://localhost:{PORT}  or  http://127.0.0.1:{PORT}", flush=True)
                print("", flush=True)
                print("  [HOW TO SHARE WITH FRIENDS]:", flush=True)
                print(f"     1. Copy the link: {public_url}", flush=True)
                print("     2. Send it to your friends via WhatsApp, Discord, or Email.", flush=True)
                print("     3. Friends can open the link in any mobile or desktop browser.", flush=True)
                print("     4. NO Python, Flask, or files needed for your friends!", flush=True)
                print("", flush=True)
                print("  [IMPORTANT HOSTING NOTES]:", flush=True)
                print("     - Keep this terminal window open while friends are using the app.", flush=True)
                print("     - If you close this window or put laptop to sleep, the link closes.", flush=True)
                print("", flush=True)
                print("  [TO STOP THE SERVER]:", flush=True)
                print("     Press Ctrl + C in this terminal window.", flush=True)
                print("========================================================================\n", flush=True)

    stderr_thread = threading.Thread(target=monitor_stream, args=(tunnel_proc.stderr,), daemon=True)
    stdout_thread = threading.Thread(target=monitor_stream, args=(tunnel_proc.stdout,), daemon=True)
    stderr_thread.start()
    stdout_thread.start()

    # Wait for URL or timeout
    start_wait = time.time()
    while not public_url and (time.time() - start_wait) < 25:
        if tunnel_proc.poll() is not None:
            print("[!] Cloudflare Tunnel process exited prematurely.", file=sys.stderr, flush=True)
            break
        time.sleep(0.5)

    if not public_url and tunnel_proc.poll() is None:
        print("\n[!] Still waiting for Cloudflare Tunnel link. Tunnel process is running.", flush=True)

    # Keep alive until Ctrl+C
    try:
        while True:
            time.sleep(1)
            if tunnel_proc.poll() is not None:
                print("[!] Tunnel process terminated.", flush=True)
                break
    except KeyboardInterrupt:
        print("\n[REALSAFE] Shutting down host server and closing Cloudflare Tunnel...", flush=True)
    finally:
        try:
            tunnel_proc.terminate()
            tunnel_proc.wait(timeout=3)
        except Exception:
            try:
                tunnel_proc.kill()
            except Exception:
                pass
        print("[REALSAFE] Host server stopped and public link deactivated successfully.", flush=True)

if __name__ == '__main__':
    main()
