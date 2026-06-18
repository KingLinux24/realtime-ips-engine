import time
import os
import json
import subprocess

from src.parse.log_parser import parse_auth_line
from src.features.window_manager import LiveFeatureWindow
from src.detection.engine import evaluate_and_score

# Track IPs that we have already blocked so we don't spam firewall rules
BLOCKED_IPS = set()

def block_ip(ip: str):
    """Bypasses UFW wrappers to inject a raw, low-level kernel block using iptables."""
    if ip in BLOCKED_IPS:
        return
       
    print(f"[!] ACTIVE DEFENSE TRIGGERED: Blocking IP {ip} via native iptables...")
    try:
        # Append an absolute DROP rule directly to the main INPUT chain
        cmd = f"iptables -I INPUT 1 -s {ip} -j DROP"
        result = subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True)
       
        BLOCKED_IPS.add(ip)
        print(f"[+] Successfully isolated attacker {ip} at the kernel level.")
    except subprocess.CalledProcessError as e:
        print(f"[-] Failed to block IP {ip}: {e.stderr.strip()}")

def follow_log(filepath):
    """Yields new lines added to the file, acting like tail -f."""
    filepath.seek(0, os.SEEK_END)
    while True:
        line = filepath.readline()
        if not line:
            time.sleep(0.1)
            continue
        yield line

def main():
    log_path = "/var/log/auth.log"
    print(f"[*] Starting live active-defense monitor against {log_path}...")
    window_tracker = LiveFeatureWindow(window_minutes=5)

    try:
        with open(log_path, "r", errors="ignore") as f:
            for raw_line in follow_log(f):
                parsed = parse_auth_line(raw_line)
                if parsed:
                    ip = parsed["src_ip"]
                    username = parsed["user"]
                    status = parsed["status"]

                    window_tracker.add_event(ip, username, status)
                    current_metrics = window_tracker.get_features(ip, username)
                   
                    alert = evaluate_and_score(current_metrics, ip, username)
                    if alert:
                        print(f"\n[!!!] SOC ALERT DETECTED [Severity: {alert['severity'].upper()}]")
                        print(json.dumps(alert, indent=2))
                       
                        # Active defense response: block any medium or high threat IPs instantly
                        if alert["severity"] in ["medium", "high"]:
                            block_ip(ip)
                       
    except PermissionError:
        print("[-] Error: Must execute this monitor runner script using 'sudo' privilege.")
    except KeyboardInterrupt:
        print("\n[*] Exiting defense monitor monitoring loop cleanly.")

if __name__ == "__main__":
    main()
