import time
import requests
import random
import sys

BACKEND_URL = "http://127.0.0.1:5050/api"

def get_host_status():
    try:
        r = requests.get(f"{BACKEND_URL}/hosts")
        if r.status_code == 200:
            return {h["ip"]: h["status"] for h in r.json()}
    except Exception as e:
        print("Error connecting to backend server:", e)
    return {}

def run_simulator():
    print("====================================================")
    print("SIH 2026 CYBER RANGE TRAFFIC GENERATOR INITIALIZED")
    print("Simulating multi-stage attack transitions...")
    print("Press Ctrl+C to stop simulation.")
    print("====================================================")
    
    step = 0
    
    while True:
        statuses = get_host_status()
        if not statuses:
            print("Backend server not reachable. Retrying in 4 seconds...")
            time.sleep(4)
            continue
            
        # 1. Simulate Public Web Server (192.168.1.20)
        web_ip = "192.168.1.20"
        web_status = statuses.get(web_ip, "ONLINE")
        
        print(f"\n[Tick {step}] Host Statuses: Web={web_status}, Finance={statuses.get('192.168.1.15', 'ONLINE')}")
        
        if web_status == "ISOLATED":
            print(f" -> [192.168.1.20] ISOLATED. Blocked all outbound/inbound traffic flow.")
        elif web_status == "PORTS_BLOCKED" and step >= 10:
            payload = {
                "hostIp": web_ip,
                "duration": 0.15,
                "src_pkts": 3,
                "dst_pkts": 3,
                "total_bytes": 400,
                "port_danger": 0.0,
                "protocol": 1.0 # TCP
            }
            try:
                requests.post(f"{BACKEND_URL}/traffic-event", json=payload)
                print(f" -> [192.168.1.20] PORTS BLOCKED. Exploit traffic dropped. Normal traffic allowed.")
            except Exception as e:
                print(f" -> [192.168.1.20] Error posting event: {e}")
        elif web_status == "RATE_LIMITED" and step >= 10:
            # Slower traffic progression
            payload = {
                "hostIp": web_ip,
                "duration": 2.4, # longer duration due to limiting
                "src_pkts": 12, # smaller pkts
                "dst_pkts": 8,
                "total_bytes": 1200, # smaller bytes
                "port_danger": 0.5,
                "protocol": 1.0
            }
            try:
                requests.post(f"{BACKEND_URL}/traffic-event", json=payload)
                print(f" -> [192.168.1.20] RATE LIMITED. Attacker flow throttled.")
            except Exception as e:
                print(f" -> [192.168.1.20] Error posting event: {e}")
        else:
            # Attack progression
            if step < 5:
                # Normal State
                payload = {
                    "hostIp": web_ip,
                    "duration": 0.15 + random.uniform(-0.02, 0.02),
                    "src_pkts": random.randint(2, 3),
                    "dst_pkts": random.randint(2, 3),
                    "total_bytes": random.randint(250, 350),
                    "port_danger": 0.0,
                    "protocol": 1.0
                }
                status_text = "Normal Web HTTP/S flows"
            elif step < 10:
                # Recon Scan
                payload = {
                    "hostIp": web_ip,
                    "duration": 0.45,
                    "src_pkts": 18,
                    "dst_pkts": 9,
                    "total_bytes": 550,
                    "port_danger": 1.0, # Active scan danger
                    "protocol": 1.0
                }
                status_text = "MALICIOUS: Network Recon Scan detected"
            elif step < 15:
                # Exploit
                payload = {
                    "hostIp": web_ip,
                    "duration": 1.25,
                    "src_pkts": 50,
                    "dst_pkts": 40,
                    "total_bytes": 5200,
                    "port_danger": 0.5,
                    "protocol": 1.0
                }
                status_text = "ATTACK: Exploiting Public-Facing HTTP Web server"
            else:
                # Lateral connection attempts
                payload = {
                    "hostIp": web_ip,
                    "duration": 2.5,
                    "src_pkts": 28,
                    "dst_pkts": 22,
                    "total_bytes": 3200,
                    "port_danger": 0.8,
                    "protocol": 1.0
                }
                status_text = "LATERAL: SMB credential scanning targeting Finance server"
                
            try:
                requests.post(f"{BACKEND_URL}/traffic-event", json=payload)
                print(f" -> [{web_ip}] {status_text}")
            except Exception as e:
                print(f" -> [{web_ip}] Error: {e}")

        # 2. Simulate Finance Database Server (192.168.1.15)
        fin_ip = "192.168.1.15"
        fin_status = statuses.get(fin_ip, "ONLINE")
        
        if fin_status == "ISOLATED":
            print(f" -> [{fin_ip}] ISOLATED. Blocked all traffic flow.")
        else:
            if step < 15:
                # Normal database traffic
                payload = {
                    "hostIp": fin_ip,
                    "duration": 0.12,
                    "src_pkts": 2,
                    "dst_pkts": 2,
                    "total_bytes": 180,
                    "port_danger": 0.0,
                    "protocol": 1.0
                }
                status_text = "Normal internal SQL query flow"
            elif step < 20:
                # Check if Web server was mitigated
                if web_status == "ONLINE":
                    payload = {
                        "hostIp": fin_ip,
                        "duration": 3.2,
                        "src_pkts": 32,
                        "dst_pkts": 28,
                        "total_bytes": 4800,
                        "port_danger": 0.8, # RDP/SMB login attempt
                        "protocol": 1.0
                    }
                    status_text = "LATERAL INTRUSION: Remote login attempt from Public Web server"
                else:
                    # Pivoting failed because Web server is quarantined
                    payload = {
                        "hostIp": fin_ip,
                        "duration": 0.1,
                        "src_pkts": 2,
                        "dst_pkts": 2,
                        "total_bytes": 160,
                        "port_danger": 0.0,
                        "protocol": 1.0
                    }
                    status_text = "Normal database flow (Pivoting blocked by mitigation)"
            else:
                # Exfiltration stage
                if web_status == "ONLINE":
                    payload = {
                        "hostIp": fin_ip,
                        "duration": 12.5,
                        "src_pkts": 260,
                        "dst_pkts": 140,
                        "total_bytes": 195000, # Big exfiltration transfer
                        "port_danger": 0.4,
                        "protocol": 1.0
                    }
                    status_text = "EXFILTRATION ACTION: Dumping financial ledgers to external server"
                else:
                    payload = {
                        "hostIp": fin_ip,
                        "duration": 0.1,
                        "src_pkts": 2,
                        "dst_pkts": 2,
                        "total_bytes": 160,
                        "port_danger": 0.0,
                        "protocol": 1.0
                    }
                    status_text = "Normal database flow (Exfiltration thwarted)"
                    
            try:
                requests.post(f"{BACKEND_URL}/traffic-event", json=payload)
                print(f" -> [{fin_ip}] {status_text}")
            except Exception as e:
                print(f" -> [{fin_ip}] Error: {e}")

        # 3. Simulate HR Workstation (192.168.1.50) - Always Normal
        hr_ip = "192.168.1.50"
        hr_status = statuses.get(hr_ip, "ONLINE")
        
        if hr_status == "ONLINE":
            payload = {
                "hostIp": hr_ip,
                "duration": 0.25 + random.uniform(-0.05, 0.05),
                "src_pkts": random.randint(2, 4),
                "dst_pkts": random.randint(2, 4),
                "total_bytes": random.randint(150, 250),
                "port_danger": 0.0,
                "protocol": 0.5 # UDP DNS/NTP request
            }
            try:
                requests.post(f"{BACKEND_URL}/traffic-event", json=payload)
            except Exception as e:
                pass

        step += 1
        time.sleep(4)

if __name__ == "__main__":
    try:
        run_simulator()
    except KeyboardInterrupt:
        print("\nSimulator stopped.")
        sys.exit(0)
