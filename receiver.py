#!/usr/bin/env python3
import argparse
import json
import select
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

MAX_BYTES = 150000
SECTIONS = ["listening ports", "nmap scan", "scheduled tasks", "users and groups", "file permissions", "firewall rules"]
latest = {}

# gets rid of unreadable chars
def clean(value):
    text = str(value)
    return "".join(char if char == "\n" or char.isprintable() else "?" for char in text[:MAX_BYTES])

# keeps port usable so I can redeploy on same port if server crashes
class Server(HTTPServer):
    allow_reuse_address = True

# sets up server's http handling
class Handler(BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.connection.settimeout(20) #20 second timeout

    # gets results and stores them on server
    def do_POST(self):
        if self.path != "/":
            self.send_error(404)
            return
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if not 0 < size <= MAX_BYTES:
                return
            data = json.loads(self.rfile.read(size))
            if not isinstance(data, dict) or not isinstance(data.get("findings"), dict):
                return
            host = clean(data.get("host", "unknown"), 120)
            findings = {section: clean(data["findings"].get(section, "Not included")) for section in SECTIONS}
            latest[host] = {"time": clean(data.get("time_utc", "?"), 80), "findings": findings}
        except (ValueError, TypeError, UnicodeError, TimeoutError, OSError):
            return
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"OK")
        print(f"\nUpdated scan from {host}")

    # don't need default logging so ignore it
    def log_message(self, format, *args):
        pass

# configures menu display
# first menu chooses host, second chooses section to execute
def menu(level, host=None):
    if level == "hosts":
        print("\n===== UBUNTU RECON SERVER =====")
        for number, name in enumerate(sorted(latest), 1):
            print(f"[{number}] {name}")
        print("[0] Exit")
        return "Select host: "
    if level == "sections":
        print(f"\nHost: {host} | Last scan: {latest[host]['time']}")
        for number, section in enumerate(SECTIONS, 1):
            print(f"[{number}] {section.title()}")
        print("[0] Back")
        return "Select scan: "
    return "Press Enter to go back: "

# handles starting of HTTP server and menu display loop
def main():
    parser = argparse.ArgumentParser(description="Ubuntu recon receiver")
    parser.add_argument("--listen", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=9000)
    args = parser.parse_args()
    try:
        server = Server((args.listen, args.port), Handler)
    except OSError as error:
        parser.exit(1, f"Cannot listen on {args.listen}:{args.port}: {error}\n")
    level, host = "hosts", None
    print(f"Listening on http://{args.listen}:{args.port}/")
    print(menu(level), end="", flush=True)
    try:
        while True:
            ready, _, _ = select.select([server, sys.stdin], [], [])
            if server in ready:
                server.handle_request()
                print(menu(level, host), end="", flush=True)
            if sys.stdin in ready:
                choice = sys.stdin.readline()
                if not choice:
                    break
                choice = choice.strip()
                if level == "hosts":
                    hosts = sorted(latest)
                    if choice == "0":
                        break
                    if choice.isdigit() and 1 <= int(choice) <= len(hosts):
                        host, level = hosts[int(choice) - 1], "sections"
                elif level == "sections":
                    if choice == "0":
                        level, host = "hosts", None
                    elif choice.isdigit() and 1 <= int(choice) <= len(SECTIONS):
                        section = SECTIONS[int(choice) - 1]
                        print(f"\n--- {section.upper()} ---\n{latest[host]['findings'][section]}")
                        level = "view"
                else:
                    level = "sections"
                print(menu(level, host), end="", flush=True)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        print("\nServer stopped; listening port released.")

if __name__ == "__main__":
    main()
