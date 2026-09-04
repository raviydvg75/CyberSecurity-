import socket
import sys
import argparse
import json
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# ANSI Colors
RESET = "\033[0m"
BOLD = "\033[1m"

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"
WHITE = "\033[97m"

# Service-specific UDP payloads to trigger real responses
UDP_PAYLOADS = {
    53: b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01",  # DNS Query
    123: b"\xe3" + b"\x00" * 47,                                                                # NTP Version 4
    137: b"\x80\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x20\x43\x4b\x41\x41" + b"\x00" * 15, # NetBIOS
    161: b"\x30\x26\x02\x01\x01\x04\x06public\xa0\x19\x02\x04\x00\x00\x00\x00\x02\x01\x00\x02\x01\x00\x30\x0e\x30\x0c\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00\x05\x00", # SNMP v2c
    1900: b'M-SEARCH * HTTP/1.1\r\nHST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n', # SSDP
    5353: b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x09_services\x07_dns-sd\x04_udp\x05local\x00\x00\x0c\x00\x01" # mDNS
}


def banner():
    print(f"""{CYAN}{BOLD}
██████╗  ██████╗ ██████╗ ████████╗
██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝
██████╔╝██║   ██║██████╔╝   ██║
██╔═══╝ ██║   ██║██╔══██╗   ██║
██║     ╚██████╔╝██║  ██║   ██║
╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝

███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███╗   ██╗███████╗██████╗
██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║████╗  ██║██╔════╝██╔══██╗
███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║██║ ╚████║███████╗██║  ██║
╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝

╔═════════════════════════════════════════════════════════════════════╗
║                         PYTHON PORT SCANNER                         ║
║                                                                     ║
║                     Developer : Rabi Bhushan Yadav                 ║
╚═════════════════════════════════════════════════════════════════════╝
{RESET}""")


def resolve_target(target):
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        print(f"{RED}[!] Could not resolve target: {target}{RESET}")
        sys.exit(1)


def parse_port_range(value):
    try:
        if "-" in value:
            start, end = value.split("-", 1)
            start = int(start)
            end = int(end)
        else:
            start = int(value)
            end = start

        if not (1 <= start <= 65535 and 1 <= end <= 65535 and start <= end):
            raise ValueError

        return start, end
    except ValueError:
        raise ValueError("Invalid port range")


def get_port_range():
    while True:
        value = input(
            f"{CYAN}Port range {WHITE}(example: 1-1024): {RESET}"
        ).strip()
        try:
            return parse_port_range(value)
        except ValueError:
            print(f"{RED}[!] Invalid port range.{RESET}")
            print(f"{YELLOW}Example: 1-1024 or 80{RESET}")


def get_service(port, protocol):
    try:
        return socket.getservbyport(port, protocol)
    except OSError:
        return "unknown"


def progress_bar(completed, total):
    width = 35
    percentage = completed / total
    filled = int(width * percentage)
    bar = "█" * filled + "-" * (width - filled)

    print(
        f"\r{CYAN}[{bar}] {percentage * 100:6.2f}% ({completed}/{total}){RESET}",
        end="",
        flush=True
    )


# TCP Scan Execution
def scan_tcp_port(target, port, timeout):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        result = sock.connect_ex((target, port))
        if result == 0:
            return {
                "port": port,
                "protocol": "TCP",
                "state": "open",
                "service": get_service(port, "tcp")
            }
    except socket.error:
        pass
    finally:
        sock.close()

    return None


def tcp_scan(target, start_port, end_port, timeout, workers):
    print(f"\n{YELLOW}{BOLD}[*] TCP Connect Scan{RESET}")
    print(f"{WHITE}[*] Threads : {workers} | Timeout : {timeout}s{RESET}\n")

    total = end_port - start_port + 1
    completed = 0
    results = []

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(scan_tcp_port, target, port, timeout): port
            for port in range(start_port, end_port + 1)
        }

        for future in as_completed(futures):
            completed += 1
            result = future.result()

            if result:
                results.append(result)

            progress_bar(completed, total)

    print()

    for res in sorted(results, key=lambda x: x["port"]):
        print(f"{GREEN}{BOLD}[+] TCP {res['port']:<6} OPEN{RESET}  {WHITE}{res['service']}{RESET}")

    return sorted(results, key=lambda item: item["port"])


# Multithreaded UDP Scan Execution
def scan_udp_port(target, port, timeout):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)

    payload = UDP_PAYLOADS.get(port, b"\x00")

    try:
        sock.sendto(payload, (target, port))
        data, _ = sock.recvfrom(1024)

        return {
            "port": port,
            "protocol": "UDP",
            "state": "open",
            "service": get_service(port, "udp")
        }
    except socket.timeout:
        if port in UDP_PAYLOADS:
            return {
                "port": port,
                "protocol": "UDP",
                "state": "open|filtered",
                "service": get_service(port, "udp")
            }
        return None
    except (socket.error, ConnectionRefusedError):
        return None
    finally:
        sock.close()


def udp_scan(target, start_port, end_port, timeout, workers):
    print(f"\n{MAGENTA}{BOLD}[*] Multithreaded UDP Scan{RESET}")
    print(f"{WHITE}[*] Threads : {workers} | Timeout : {timeout}s{RESET}\n")

    total = end_port - start_port + 1
    completed = 0
    results = []

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(scan_udp_port, target, port, timeout): port
            for port in range(start_port, end_port + 1)
        }

        for future in as_completed(futures):
            completed += 1
            result = future.result()

            if result:
                results.append(result)

            progress_bar(completed, total)

    print()

    for res in sorted(results, key=lambda x: x["port"]):
        if res["state"] == "open":
            print(f"{GREEN}{BOLD}[+] UDP {res['port']:<6} OPEN{RESET}  {WHITE}{res['service']}{RESET}")
        else:
            print(f"{YELLOW}[?] UDP {res['port']:<6} OPEN|FILTERED{RESET}  {WHITE}{res['service']}{RESET}")

    return sorted(results, key=lambda item: item["port"])


def select_mode():
    print(f"""
{BLUE}{BOLD}Select Scan Mode
================{RESET}

{WHITE}[1]{RESET} Normal TCP Scan
{WHITE}[2]{RESET} Fast TCP Scan
{WHITE}[3]{RESET} Multithreaded UDP Scan
{WHITE}[4]{RESET} TCP + UDP Scan
""")

    while True:
        choice = input(f"{CYAN}Choice [1-4]: {RESET}").strip()
        if choice in ("1", "2", "3", "4"):
            return choice
        print(f"{RED}[!] Invalid choice.{RESET}")


def save_txt(filename, target, ip, start_port, end_port, mode, results):
    with open(filename, "w") as file:
        file.write("PYTHON PORT SCANNER\n")
        file.write("Developed by Rabi Bhushan Yadav\n")
        file.write("=" * 55 + "\n")
        file.write(f"Target      : {target}\n")
        file.write(f"IP Address  : {ip}\n")
        file.write(f"Port Range  : {start_port}-{end_port}\n")
        file.write(f"Scan Mode   : {mode}\n")
        file.write(f"Scan Time   : {datetime.now()}\n")
        file.write("\nRESULTS\n")
        file.write("-" * 55 + "\n")

        for result in results:
            file.write(
                f"{result['protocol']:<5} "
                f"{result['port']:<6} "
                f"{result['state']:<14} "
                f"{result['service']}\n"
            )

    print(f"{GREEN}[+] TXT saved: {filename}{RESET}")


def save_json(filename, target, ip, start_port, end_port, mode, results):
    output = {
        "scanner": "Python Port Scanner",
        "developer": "Rabi Bhushan Yadav",
        "target": target,
        "ip_address": ip,
        "port_range": f"{start_port}-{end_port}",
        "scan_mode": mode,
        "scan_time": str(datetime.now()),
        "results": results
    }

    with open(filename, "w") as file:
        json.dump(output, file, indent=4)

    print(f"{GREEN}[+] JSON saved: {filename}{RESET}")


def get_arguments():
    parser = argparse.ArgumentParser(
        description="Python TCP/UDP Port Scanner developed by Rabi Bhushan Yadav"
    )
    parser.add_argument("target", nargs="?", help="Target IP address or hostname")
    parser.add_argument("-p", "--ports", help="Port range, e.g. 1-1024")
    parser.add_argument(
        "-m",
        "--mode",
        choices=["tcp", "fast", "udp", "both"],
        help="Scan mode: tcp, fast, udp, both"
    )
    parser.add_argument("-w", "--workers", type=int, default=100, help="Number of worker threads")
    parser.add_argument("-t", "--timeout", type=float, default=0.5, help="Socket timeout in seconds")
    parser.add_argument("--txt", action="store_true", help="Save results to scan_results.txt")
    parser.add_argument("--json", action="store_true", help="Save results to scan_results.json")

    return parser.parse_args()


def main():
    args = get_arguments()
    banner()

    target_input = args.target if args.target else input(f"{CYAN}Target IP / Hostname: {RESET}").strip()

    if not target_input:
        print(f"{RED}[!] Target cannot be empty.{RESET}")
        sys.exit(1)

    ip = resolve_target(target_input)

    if args.ports:
        try:
            start_port, end_port = parse_port_range(args.ports)
        except ValueError:
            print(f"{RED}[!] Invalid port range.{RESET}")
            sys.exit(1)
    else:
        start_port, end_port = get_port_range()

    mode = args.mode if args.mode else select_mode()

    print(f"""
{BLUE}{BOLD}Target      : {WHITE}{target_input}
{BLUE}IP Address  : {WHITE}{ip}
{BLUE}Port Range  : {WHITE}{start_port}-{end_port}
{BLUE}Scan Mode   : {WHITE}{mode}
{BLUE}Started     : {WHITE}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
{RESET}""")

    all_results = []

    if mode in ("1", "tcp"):
        results = tcp_scan(
            ip, start_port, end_port, timeout=args.timeout, workers=args.workers
        )
        all_results.extend(results)

    elif mode in ("2", "fast"):
        results = tcp_scan(
            ip, start_port, end_port, timeout=0.15, workers=args.workers
        )
        all_results.extend(results)

    elif mode in ("3", "udp"):
        results = udp_scan(
            ip, start_port, end_port, timeout=args.timeout, workers=args.workers
        )
        all_results.extend(results)

    elif mode in ("4", "both"):
        tcp_results = tcp_scan(
            ip, start_port, end_port, timeout=args.timeout, workers=args.workers
        )
        all_results.extend(tcp_results)

        udp_results = udp_scan(
            ip, start_port, end_port, timeout=args.timeout, workers=args.workers
        )
        all_results.extend(udp_results)

    if args.txt:
        save_txt("scan_results.txt", target_input, ip, start_port, end_port, mode, all_results)

    if args.json:
        save_json("scan_results.json", target_input, ip, start_port, end_port, mode, all_results)

    tcp_open = sum(1 for r in all_results if r["protocol"] == "TCP" and r["state"] == "open")
    udp_open = sum(1 for r in all_results if r["protocol"] == "UDP" and r["state"] == "open")
    udp_filtered = sum(1 for r in all_results if r["protocol"] == "UDP" and r["state"] == "open|filtered")

    print(f"""
{CYAN}{BOLD}
╔════════════════════════════════════════╗
║               SCAN SUMMARY             ║
╚════════════════════════════════════════╝
{RESET}
{GREEN}[+] TCP Open          : {tcp_open}{RESET}
{GREEN}[+] UDP Open          : {udp_open}{RESET}
{YELLOW}[?] UDP Open|Filtered : {udp_filtered}{RESET}

{GREEN}{BOLD}[✓] Scan completed.{RESET}
""")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{RED}{BOLD}[!] Scan interrupted by user.{RESET}")
        sys.exit(0)
