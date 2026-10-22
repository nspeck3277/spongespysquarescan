#!/usr/bin/env python3
import argparse
import json
import platform
import re
import shutil
import socket
import stat
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import Request, urlopen

MAX_OUTPUT = 12000

# simplifies running of commands and does error handling
def run(command, timeout=15):
    if not shutil.which(command[0]):
        return f"Not installed: {command[0]}"
    try:
        result = subprocess.run(command, capture_output=True, text=True, errors="replace", timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as error:
        return f"Error: {error}"
    output = result.stdout.strip()
    if result.stderr:
        output += f"\nERROR: {result.stderr.strip()}"
    return (output.strip() or "(no output)")[:MAX_OUTPUT]

# looks for any listening TCP/UDP ports and formats the command results
def listening_ports():
    output = run(["ss", "-H", "-tulnp"])
    # handles ss not working
    if output.startswith(("Not installed:", "Error:")) or output == "(no output)":
        return output
    # formatting
    widths = (6, 8, 36, 7, 23, 8)
    def row(items):
        return "  ".join(f"{value:<{width}}" for value, width in zip(items, widths)).rstrip()
    lines = [row(("PROTO", "STATE", "LOCAL ADDRESS", "PORT", "PROCESS", "PID")), row(["-" * n for n in widths])]
    for line in output.splitlines():
        fields = line.split(None, 6)
        if len(fields) < 6:
            lines.append(line)
            continue
        # grabs ip address and port number from output
        address, separator, port = fields[4].rpartition(":") 
        if not separator:
            address, port = fields[4], "?"
        # grabs names and PIDs for each port
        owners = re.findall(r'\("([^"\n]+)",pid=(\d+)', fields[6] if len(fields) > 6 else "")
        name, pid = owners[0] if owners else ("-", "-")
        if len(owners) > 1:
            name += f" (+{len(owners) - 1})"
        lines.append(row((fields[0], fields[1], address, port, name, pid)))
    return "\n".join(lines)[:MAX_OUTPUT]

# scans top 100 most common TCP ports
def nmap_scan(target):
    return run(["nmap", "-sT", "-Pn", "-n", "--top-ports", "100", "--max-retries", "1", "--host-timeout", "90s", target], timeout=110)

# looks for cronjob and systemd timers on the host.
# formats them for report
def scheduled_tasks():
    paths = [Path("/etc/crontab")]
    for folder in ("/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly", "/var/spool/cron/crontabs"):
        try:
            paths.extend(p for p in sorted(Path(folder).iterdir())[:50] if p.is_file())
        except OSError:
            pass
    cron = "\n".join(str(p) for p in paths if p.is_file()) or "No cron files found"
    timers = run(["systemctl", "list-timers", "--all", "--no-pager"])
    return f"TIMERS:\n{timers}\nCRON FILES:\n{cron}"[:MAX_OUTPUT]

# just cats users and groups 
def users_and_groups():
    return f"USERS:\n{run(['cat', '/etc/passwd'])}\nGROUPS:\n{run(['cat', '/etc/group'])}"

# looks for permissions of important system files
def file_permissions():
    paths = [Path(p) for p in ("/etc/passwd", "/etc/shadow", "/etc/group", "/etc/sudoers", "/etc/ssh/sshd_config")]
    for folder in ("/etc/sudoers.d", "/etc/ssh/sshd_config.d"):
        paths.extend(p for p in sorted(Path(folder).glob("*"))[:25] if p.is_file())
    output = []
    for path in paths:
        try:
            info = path.lstat()
            output.append(f"{stat.S_IMODE(info.st_mode):04o} uid={info.st_uid} gid={info.st_gid} {path}")
        except OSError as error:
            output.append(f"{path}: {error}")
    return "\n".join(output)[:MAX_OUTPUT]

# checks ufw, nftables, and iptables for any configured firewall rules
def firewall_rules():
    return "\n".join(("UFW:\n" + run(["ufw", "status", "verbose"]), "NFTABLES:\n" + run(["nft", "list", "ruleset"]), "IPTABLES:\n" + run(["iptables", "-S"])))

# runs all the scans on specified target
def scan(target):
    return {"listening ports": listening_ports(), "nmap scan": nmap_scan(target), "scheduled tasks": scheduled_tasks(), "users and groups": users_and_groups(), "file permissions": file_permissions(), "firewall rules": firewall_rules()}

# sends results of scan command to specified server using HTTP POST
def send(server, results):
    report = {"host": socket.gethostname(), "system": platform.platform(), "time_utc": datetime.now(timezone.utc).isoformat(), "findings": results}
    request = Request(server, data=json.dumps(report).encode("utf-8"), headers={"Content-Type": "application/json"})
    with urlopen(request, timeout=20) as response:
        if response.status != 200:
            raise RuntimeError(f"Server returned HTTP {response.status}")

# runs the scanner
def main():
    parser = argparse.ArgumentParser(description="Ubuntu reconnaissance scanner")
    parser.add_argument("--server", required=True)
    parser.add_argument("--target", default="127.0.0.1")
    args = parser.parse_args()
    try:
        send(args.server, scan(args.target))
    except Exception as error:
        print(f"Could not send scan: {error}", file=sys.stderr)
        return 1
    return 0

if __name__ == "__main__":
    main()
