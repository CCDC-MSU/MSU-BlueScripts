#!/usr/bin/env python3
"""TCDC Service Monitor — real-time service health checker."""

import argparse
import ftplib
import os
import signal
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

import paramiko
import psycopg2
import requests
import yaml

# ── ANSI colors ──────────────────────────────────────────────────────────────

C_RESET  = "\033[0m"
C_RED    = "\033[91m"
C_GREEN  = "\033[92m"
C_YELLOW = "\033[93m"
C_CYAN   = "\033[96m"
C_BOLD   = "\033[1m"
C_DIM    = "\033[2m"

# ── Constants ────────────────────────────────────────────────────────────────

PING_TIMEOUT  = 2   # seconds
PORT_TIMEOUT  = 3
SVC_TIMEOUT   = 5
STATE_UP       = "UP"
STATE_DOWN     = "DOWN"
STATE_DEGRADED = "DEGR"

# ── Config ───────────────────────────────────────────────────────────────────

CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "monitor-config.yaml")

def load_config(path=CONFIG_PATH):
    with open(path) as f:
        return yaml.safe_load(f)

# ── Check functions ──────────────────────────────────────────────────────────
# Each returns (ok: bool, msg: str)

def check_ping(host):
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", str(PING_TIMEOUT), host],
            capture_output=True, text=True, timeout=PING_TIMEOUT + 1,
        )
        if result.returncode == 0:
            # extract rtt from output
            for line in result.stdout.splitlines():
                if "time=" in line:
                    ms = line.split("time=")[1].split()[0]
                    return True, f"{ms}ms"
            return True, "ok"
        return False, result.stderr.strip().splitlines()[-1] if result.stderr.strip() else "no reply"
    except subprocess.TimeoutExpired:
        return False, "ping timeout"
    except Exception as e:
        return False, str(e)


def check_port(host, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(PORT_TIMEOUT)
        sock.connect((host, port))
        sock.close()
        return True, f"port {port} open"
    except socket.timeout:
        return False, f"port {port} timeout"
    except ConnectionRefusedError:
        return False, f"port {port} refused"
    except Exception as e:
        return False, f"port {port}: {e}"


def check_http(host, port, path, expect, **_kw):
    try:
        url = f"http://{host}:{port}{path}"
        resp = requests.get(url, timeout=SVC_TIMEOUT)
        if resp.status_code != 200:
            return False, f"HTTP {resp.status_code}"
        if expect and expect not in resp.text:
            return False, f"expected '{expect}' not in response ({len(resp.text)} bytes)"
        return True, f"HTTP 200, matched '{expect}'"
    except requests.Timeout:
        return False, "HTTP timeout"
    except requests.ConnectionError as e:
        return False, f"HTTP conn error: {e}"
    except Exception as e:
        return False, f"HTTP: {e}"


def check_ftp(host, port, user, password, **_kw):
    try:
        ftp = ftplib.FTP()
        ftp.connect(host, port, timeout=SVC_TIMEOUT)
        banner = ftp.getwelcome()
        ftp.login(user, password)
        files = ftp.nlst()
        ftp.quit()
        return True, f"FTP login ok, {len(files)} entries"
    except ftplib.error_perm as e:
        return False, f"FTP auth failed: {e}"
    except Exception as e:
        return False, f"FTP: {e}"


def check_ssh(host, port, user, password, **_kw):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(host, port=port, username=user, password=password,
                       timeout=SVC_TIMEOUT, look_for_keys=False, allow_agent=False)
        _stdin, stdout, _stderr = client.exec_command("whoami", timeout=SVC_TIMEOUT)
        output = stdout.read().decode().strip()
        client.close()
        if output:
            return True, f"SSH ok (whoami={output})"
        return False, "SSH: empty whoami"
    except paramiko.AuthenticationException:
        return False, "SSH auth failed"
    except paramiko.SSHException as e:
        return False, f"SSH error: {e}"
    except Exception as e:
        return False, f"SSH: {e}"


def check_postgres(host, port, user, password, dbname="directory_search", query="SELECT 1", **_kw):
    try:
        conn = psycopg2.connect(
            host=host, port=port, user=user, password=password,
            dbname=dbname, connect_timeout=SVC_TIMEOUT,
        )
        cur = conn.cursor()
        cur.execute(query)
        row = cur.fetchone()
        cur.close()
        conn.close()
        if row:
            return True, f"PG ok (result={row[0]})"
        return False, "PG: empty result"
    except psycopg2.OperationalError as e:
        msg = str(e).strip().splitlines()[0] if str(e).strip() else "PG operational error"
        return False, f"PG: {msg}"
    except Exception as e:
        return False, f"PG: {e}"


def check_helper(host, port, **_kw):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(SVC_TIMEOUT)
        sock.connect((host, port))
        banner = sock.recv(1024).decode().strip()
        sock.sendall(b"PING\n")
        response = sock.recv(1024).decode().strip()
        sock.close()
        if response.startswith("HELPER:"):
            return True, f"Helper ok (banner='{banner}')"
        return False, f"Helper: unexpected response '{response}'"
    except socket.timeout:
        return False, "Helper: timeout"
    except ConnectionRefusedError:
        return False, "Helper: connection refused"
    except Exception as e:
        return False, f"Helper: {e}"


CHECK_FUNCTIONS = {
    "http":     check_http,
    "ftp":      check_ftp,
    "ssh":      check_ssh,
    "postgres": check_postgres,
    "helper":   check_helper,
}

# ── Three-tier check runner ──────────────────────────────────────────────────

def run_service_check(name, svc_cfg, log_level):
    """Run ping → port → service check. Returns dict with results."""
    host = svc_cfg["host"]
    check_type = list(svc_cfg["checks"].keys())[0]
    check_cfg = svc_cfg["checks"][check_type]
    port = check_cfg.get("port")

    result = {
        "name": name,
        "host": host,
        "ping": (False, ""),
        "port": (False, ""),
        "service": (False, ""),
        "state": STATE_DOWN,
        "check_type": check_type,
    }

    # Tier 1: Ping
    ok, msg = check_ping(host)
    result["ping"] = (ok, msg)
    if log_level == "debug":
        _debug_log(f"  [{name}] PING {'OK' if ok else 'FAIL'}: {msg}")
    if not ok:
        result["state"] = STATE_DOWN
        return result

    # Tier 2: Port
    if port:
        ok, msg = check_port(host, port)
        result["port"] = (ok, msg)
        if log_level == "debug":
            _debug_log(f"  [{name}] PORT {'OK' if ok else 'FAIL'}: {msg}")
        if not ok:
            result["state"] = STATE_DOWN
            return result
    else:
        result["port"] = (True, "n/a")

    # Tier 3: Service-level check
    check_fn = CHECK_FUNCTIONS.get(check_type)
    if check_fn:
        ok, msg = check_fn(host=host, **check_cfg)
        result["service"] = (ok, msg)
        if log_level == "debug":
            _debug_log(f"  [{name}] SERVICE {'OK' if ok else 'FAIL'}: {msg}")
        result["state"] = STATE_UP if ok else STATE_DEGRADED
    else:
        result["service"] = (False, f"unknown check type: {check_type}")
        result["state"] = STATE_DEGRADED

    return result

# ── Display helpers ──────────────────────────────────────────────────────────

_debug_buffer = []

def _debug_log(msg):
    _debug_buffer.append(msg)


def strip_ansi(text):
    import re
    return re.sub(r'\033\[[0-9;]*m', '', text)


def state_color(state):
    if state == STATE_UP:
        return C_GREEN
    if state == STATE_DEGRADED:
        return C_YELLOW
    return C_RED


def tick_mark(ok):
    return f"{C_GREEN}✓{C_RESET}" if ok else f"{C_RED}✗{C_RESET}"


def dash_mark():
    return f"{C_DIM}-{C_RESET}"


def format_table(results, cycle, uptime_stats):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    w = 20  # name column width

    lines = []
    header_line = f"{C_CYAN}─── {now} ── Cycle #{cycle} {'─' * 36}{C_RESET}"
    lines.append(header_line)
    lines.append(
        f" {C_BOLD}{'SERVICE':<{w}} {'PING':^6} {'PORT':^6} {'SVC':^6}  {'STATE':^6}  {'UPTIME':>7}{C_RESET}"
    )

    for r in results:
        name = r["name"]
        ping_ok = r["ping"][0]
        port_ok = r["port"][0]
        svc_ok  = r["service"][0]
        state   = r["state"]

        # decide what to show for each tier
        ping_col = tick_mark(ping_ok)
        port_col = tick_mark(port_ok) if ping_ok else dash_mark()
        svc_col  = tick_mark(svc_ok)  if (ping_ok and port_ok) else dash_mark()

        sc = state_color(state)
        pct = uptime_stats.get(name, {}).get("pct", 100.0)
        pct_color = C_GREEN if pct >= 95 else (C_YELLOW if pct >= 80 else C_RED)

        lines.append(
            f" {name:<{w}} {ping_col:^15} {port_col:^15} {svc_col:^15}  "
            f"{sc}{state:^6}{C_RESET}  {pct_color}{pct:6.1f}%{C_RESET}"
        )

    lines.append(f"{C_CYAN}{'─' * 64}{C_RESET}")
    return "\n".join(lines)


def format_transition(name, old_state, new_state, msg):
    sc = state_color(new_state)
    return f"{C_BOLD}  !! {name}: {old_state} → {sc}{new_state}{C_RESET}{C_BOLD} — {msg}{C_RESET}"


def format_debug_lines():
    global _debug_buffer
    lines = list(_debug_buffer)
    _debug_buffer = []
    return lines

# ── State & uptime tracking ─────────────────────────────────────────────────

class StateTracker:
    def __init__(self):
        self.states = {}      # name -> current state
        self.stats = {}       # name -> {"total": int, "up": int, "pct": float}

    def update(self, name, new_state):
        old = self.states.get(name)
        self.states[name] = new_state

        if name not in self.stats:
            self.stats[name] = {"total": 0, "up": 0, "pct": 100.0}

        s = self.stats[name]
        s["total"] += 1
        if new_state == STATE_UP:
            s["up"] += 1
        s["pct"] = (s["up"] / s["total"]) * 100.0

        changed = old is not None and old != new_state
        return changed, old

    def summary(self):
        lines = [f"\n{C_CYAN}{C_BOLD}═══ Final Uptime Summary ═══{C_RESET}"]
        for name, s in self.stats.items():
            pct = s["pct"]
            pc = C_GREEN if pct >= 95 else (C_YELLOW if pct >= 80 else C_RED)
            lines.append(f"  {name:<20} {pc}{pct:6.1f}%{C_RESET}  ({s['up']}/{s['total']} checks)")
        lines.append(f"{C_CYAN}{'═' * 50}{C_RESET}")
        return "\n".join(lines)

# ── Logging ──────────────────────────────────────────────────────────────────

class FileLogger:
    def __init__(self, path):
        self.path = path
        self.fh = open(path, "a") if path else None

    def write(self, text):
        if self.fh:
            self.fh.write(strip_ansi(text) + "\n")
            self.fh.flush()

    def close(self):
        if self.fh:
            self.fh.close()

# ── Main loop ────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="TCDC Service Monitor")
    parser.add_argument("--config", default=CONFIG_PATH, help="Path to YAML config")
    parser.add_argument("--level", choices=["debug", "info", "production"], help="Override log level")
    args = parser.parse_args()

    config_path = args.config
    cfg = load_config(config_path)
    config_mtime = os.path.getmtime(config_path)

    log_level = args.level or cfg.get("log_level", "info")
    interval  = cfg.get("interval", 10)
    alert_on  = cfg.get("alert_sound", True)
    log_file  = cfg.get("log_file", "monitor.log")

    logger = FileLogger(log_file)
    tracker = StateTracker()
    cycle = 0
    running = True

    # Suppress paramiko logging noise
    import logging
    logging.getLogger("paramiko").setLevel(logging.CRITICAL)

    def shutdown(sig, frame):
        nonlocal running
        running = False

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    services = cfg.get("services", {})
    svc_names = list(services.keys())

    print(f"{C_CYAN}{C_BOLD}TCDC Monitor started{C_RESET} — "
          f"team {cfg.get('team_id', '?')}, {len(svc_names)} services, "
          f"{interval}s interval, level={log_level}")
    print(f"Config: {config_path}")
    print(f"Log:    {log_file}")
    print(f"Press Ctrl+C to stop.\n")
    logger.write(f"[{datetime.now().isoformat()}] Monitor started — {len(svc_names)} services, {interval}s interval")

    while running:
        cycle += 1
        cycle_start = time.time()

        # Hot-reload config
        try:
            current_mtime = os.path.getmtime(config_path)
            if current_mtime != config_mtime:
                cfg = load_config(config_path)
                config_mtime = current_mtime
                services = cfg.get("services", {})
                svc_names = list(services.keys())
                interval = cfg.get("interval", 10)
                alert_on = cfg.get("alert_sound", True)
                if not args.level:
                    log_level = cfg.get("log_level", "info")
                msg = f"{C_YELLOW}Config reloaded{C_RESET} — {len(svc_names)} services, {interval}s interval, level={log_level}"
                print(msg)
                logger.write(f"[{datetime.now().isoformat()}] Config reloaded")
        except Exception as e:
            print(f"{C_RED}Config reload error: {e}{C_RESET}")

        # Run checks in parallel
        results = []
        if log_level == "debug":
            print(f"\n{C_DIM}[debug] Cycle {cycle} — running checks...{C_RESET}")

        with ThreadPoolExecutor(max_workers=len(svc_names)) as pool:
            futures = {
                pool.submit(run_service_check, name, services[name], log_level): name
                for name in svc_names
            }
            for future in as_completed(futures):
                try:
                    results.append(future.result())
                except Exception as e:
                    name = futures[future]
                    results.append({
                        "name": name, "host": services[name]["host"],
                        "ping": (False, ""), "port": (False, ""),
                        "service": (False, str(e)), "state": STATE_DOWN,
                        "check_type": "error",
                    })

        # Sort results to maintain consistent order
        order = {name: i for i, name in enumerate(svc_names)}
        results.sort(key=lambda r: order.get(r["name"], 999))

        # Update state, detect transitions
        transitions = []
        for r in results:
            changed, old_state = tracker.update(r["name"], r["state"])
            if changed:
                # pick the most relevant message
                if r["state"] == STATE_DOWN:
                    # find the first failed tier
                    if not r["ping"][0]:
                        msg = r["ping"][1]
                    elif not r["port"][0]:
                        msg = r["port"][1]
                    else:
                        msg = r["service"][1]
                elif r["state"] == STATE_DEGRADED:
                    msg = r["service"][1]
                else:
                    msg = "recovered"
                transitions.append((r["name"], old_state, r["state"], msg))

        # Display based on log level
        if log_level == "debug":
            for line in format_debug_lines():
                print(line)
            table = format_table(results, cycle, tracker.stats)
            print(table)
            logger.write(strip_ansi(table))

        elif log_level == "info":
            table = format_table(results, cycle, tracker.stats)
            print(table)
            logger.write(strip_ansi(table))

        # Transitions shown in all modes
        for name, old_s, new_s, msg in transitions:
            tline = format_transition(name, old_s, new_s, msg)
            print(tline)
            logger.write(f"[{datetime.now().isoformat()}] {strip_ansi(tline)}")

            # Audio alert on degradation
            if new_s in (STATE_DOWN, STATE_DEGRADED) and alert_on:
                print("\a", end="", flush=True)

        if log_level == "production" and not transitions:
            # In production mode with no changes, just print a dot to show we're alive
            if cycle % 6 == 0:  # every ~60s
                now = datetime.now().strftime("%H:%M:%S")
                print(f"{C_DIM}  [{now}] all checks passed (cycle {cycle}){C_RESET}")

        # Sleep for remaining interval
        elapsed = time.time() - cycle_start
        sleep_time = max(0, interval - elapsed)
        if sleep_time > 0 and running:
            try:
                time.sleep(sleep_time)
            except KeyboardInterrupt:
                running = False

    # Shutdown
    print(tracker.summary())
    logger.write(strip_ansi(tracker.summary()))
    logger.write(f"[{datetime.now().isoformat()}] Monitor stopped")
    logger.close()
    print(f"\n{C_DIM}Monitor stopped. Log saved to {log_file}{C_RESET}")


if __name__ == "__main__":
    main()
