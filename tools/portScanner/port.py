import socket
import sys
import argparse
import json
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed


# Colors

RESET = "\033[0m"
BOLD = "\033[1m"

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"
WHITE = "\033[97m"


# Banner

def banner():

    print(f"""{CYAN}{BOLD}

██████╗  ██████╗ ██████╗ ████████╗
██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝
██████╔╝██║   ██║██████╔╝   ██║
██╔═══╝ ██║   ██║██╔══██╗   ██║
██║     ╚██████╔╝██║  ██║   ██║
╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝

███████╗ ██████╗ █████╗ ███╗   ██╗
██╔════╝██╔════╝██╔══██╗████╗  ██║
███████╗██║     ███████║██╔██╗ ██║
╚════██║██║     ██╔══██║██║╚██╗██║
███████║╚██████╗██║  ██║██║ ╚████║
╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝

╔════════════════════════════════════════════════════╗
║              PYTHON PORT SCANNER                  ║
║                                                    ║
║          Developed by Rabi Bhushan Yadav          ║
╚════════════════════════════════════════════════════╝

{RESET}""")


# Target Resolution

def resolve_target(target):

    try:
        return socket.gethostbyname(target)

    except socket.gaierror:

        print(
            f"{RED}[!] Could not resolve target: "
            f"{target}{RESET}"
        )

        sys.exit(1)


# Port Range

def parse_port_range(value):

    try:

        if "-" in value:

            start, end = value.split("-", 1)

            start = int(start)
            end = int(end)

        else:

            start = int(value)
            end = start

        if not (
            1 <= start <= 65535
            and 1 <= end <= 65535
            and start <= end
        ):
            raise ValueError

        return start, end

    except ValueError:

        raise ValueError(
            "Invalid port range"
        )


def get_port_range():

    while True:

        value = input(
            f"{CYAN}"
            f"Port range "
            f"{WHITE}(example: 1-1024): "
            f"{RESET}"
        ).strip()

        try:

            return parse_port_range(value)

        except ValueError:

            print(
                f"{RED}"
                f"[!] Invalid port range."
                f"{RESET}"
            )

            print(
                f"{YELLOW}"
                f"Example: 1-1024 or 80"
                f"{RESET}"
            )


# Service Detection

def get_service(port, protocol):

    try:

        return socket.getservbyport(
            port,
            protocol
        )

    except OSError:

        return "unknown"


# Progress Bar

def progress_bar(completed, total):

    width = 35

    percentage = completed / total

    filled = int(
        width * percentage
    )

    bar = (
        "█" * filled
        + "-" * (width - filled)
    )

    print(
        f"\r{CYAN}"
        f"[{bar}] "
        f"{percentage * 100:6.2f}% "
        f"({completed}/{total})"
        f"{RESET}",
        end="",
        flush=True
    )


# TCP Single Port

def scan_tcp_port(
    target,
    port,
    timeout
):

    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    sock.settimeout(timeout)

    try:

        result = sock.connect_ex(
            (target, port)
        )

        if result == 0:

            return {
                "port": port,
                "protocol": "TCP",
                "state": "open",
                "service": get_service(
                    port,
                    "tcp"
                )
            }

    except socket.error:

        pass

    finally:

        sock.close()

    return None


# Multithreaded TCP Scan

def tcp_scan(
    target,
    start_port,
    end_port,
    timeout,
    workers
):

    print(
        f"\n{YELLOW}{BOLD}"
        f"[*] TCP Connect Scan"
        f"{RESET}"
    )

    print(
        f"{WHITE}"
        f"[*] Threads : {workers}"
        f"{RESET}\n"
    )

    total = (
        end_port - start_port + 1
    )

    completed = 0
    results = []

    with ThreadPoolExecutor(
        max_workers=workers
    ) as executor:

        futures = [
            executor.submit(
                scan_tcp_port,
                target,
                port,
                timeout
            )
            for port in range(
                start_port,
                end_port + 1
            )
        ]

        for future in as_completed(
            futures
        ):

            completed += 1

            result = future.result()

            if result:

                results.append(result)

                print(
                    f"\n{GREEN}{BOLD}"
                    f"[+] TCP "
                    f"{result['port']:<6}"
                    f"OPEN"
                    f"{RESET}  "
                    f"{WHITE}"
                    f"{result['service']}"
                    f"{RESET}"
                )

            progress_bar(
                completed,
                total
            )

    print()

    return sorted(
        results,
        key=lambda item: item["port"]
    )


# UDP Single Port

def scan_udp_port(
    target,
    port,
    timeout=1
):

    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_DGRAM
    )

    sock.settimeout(timeout)

    try:

        sock.sendto(
            b"",
            (target, port)
        )

        try:

            data, address = \
                sock.recvfrom(1024)

            return {
                "port": port,
                "protocol": "UDP",
                "state": "open",
                "service": get_service(
                    port,
                    "udp"
                )
            }

        except socket.timeout:

            return {
                "port": port,
                "protocol": "UDP",
                "state": "open|filtered",
                "service": get_service(
                    port,
                    "udp"
                )
            }

    except socket.error:

        return None

    finally:

        sock.close()


# UDP Scan

def udp_scan(
    target,
    start_port,
    end_port,
    timeout=1
):

    print(
        f"\n{MAGENTA}{BOLD}"
        f"[*] UDP Scan"
        f"{RESET}\n"
    )

    total = (
        end_port - start_port + 1
    )

    completed = 0
    results = []

    for port in range(
        start_port,
        end_port + 1
    ):

        result = scan_udp_port(
            target,
            port,
            timeout
        )

        completed += 1

        if result:

            results.append(result)

            if result["state"] == "open":

                print(
                    f"\n{GREEN}{BOLD}"
                    f"[+] UDP "
                    f"{port:<6}"
                    f"OPEN"
                    f"{RESET}  "
                    f"{WHITE}"
                    f"{result['service']}"
                    f"{RESET}"
                )

            else:

                print(
                    f"\n{YELLOW}"
                    f"[?] UDP "
                    f"{port:<6}"
                    f"OPEN|FILTERED"
                    f"{RESET}"
                )

        progress_bar(
            completed,
            total
        )

    print()

    return results


# Interactive Mode

def select_mode():

    print(
        f"""
{BLUE}{BOLD}
Select Scan Mode
================

{WHITE}[1]{RESET} Normal TCP Scan
{WHITE}[2]{RESET} Fast TCP Scan
{WHITE}[3]{RESET} UDP Scan
{WHITE}[4]{RESET} TCP + UDP Scan

"""
    )

    while True:

        choice = input(
            f"{CYAN}"
            f"Choice [1-4]: "
            f"{RESET}"
        ).strip()

        if choice in (
            "1",
            "2",
            "3",
            "4"
        ):

            return choice

        print(
            f"{RED}"
            f"[!] Invalid choice."
            f"{RESET}"
        )


# Save TXT

def save_txt(
    filename,
    target,
    ip,
    start_port,
    end_port,
    mode,
    results
):

    with open(
        filename,
        "w"
    ) as file:

        file.write(
            "PYTHON PORT SCANNER\n"
        )

        file.write(
            "Developed by "
            "Rabi Bhushan Yadav\n"
        )

        file.write(
            "=" * 55
            + "\n"
        )

        file.write(
            f"Target      : {target}\n"
        )

        file.write(
            f"IP Address  : {ip}\n"
        )

        file.write(
            f"Port Range  : "
            f"{start_port}-{end_port}\n"
        )

        file.write(
            f"Scan Mode   : {mode}\n"
        )

        file.write(
            f"Scan Time   : "
            f"{datetime.now()}\n"
        )

        file.write(
            "\nRESULTS\n"
        )

        file.write(
            "-" * 55
            + "\n"
        )

        for result in results:

            file.write(
                f"{result['protocol']:<5} "
                f"{result['port']:<6} "
                f"{result['state']:<14} "
                f"{result['service']}\n"
            )

    print(
        f"{GREEN}"
        f"[+] TXT saved: {filename}"
        f"{RESET}"
    )


# Save JSON

def save_json(
    filename,
    target,
    ip,
    start_port,
    end_port,
    mode,
    results
):

    output = {

        "scanner":
            "Python Port Scanner",

        "developer":
            "Rabi Bhushan Yadav",

        "target":
            target,

        "ip_address":
            ip,

        "port_range":
            f"{start_port}-{end_port}",

        "scan_mode":
            mode,

        "scan_time":
            str(datetime.now()),

        "results":
            results
    }

    with open(
        filename,
        "w"
    ) as file:

        json.dump(
            output,
            file,
            indent=4
        )

    print(
        f"{GREEN}"
        f"[+] JSON saved: {filename}"
        f"{RESET}"
    )


# Arguments

def get_arguments():

    parser = argparse.ArgumentParser(

        description=(
            "Python TCP/UDP Port Scanner "
            "developed by Rabi Bhushan Yadav"
        )
    )

    parser.add_argument(
        "target",
        nargs="?",
        help="Target IP address or hostname"
    )

    parser.add_argument(
        "-p",
        "--ports",
        help="Port range, e.g. 1-1024"
    )

    parser.add_argument(
        "-m",
        "--mode",
        choices=[
            "tcp",
            "fast",
            "udp",
            "both"
        ],
        help=(
            "Scan mode: "
            "tcp, fast, udp, both"
        )
    )

    parser.add_argument(
        "-w",
        "--workers",
        type=int,
        default=100,
        help="Number of TCP worker threads"
    )

    parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=0.5,
        help="TCP connection timeout"
    )

    parser.add_argument(
        "--txt",
        action="store_true",
        help="Save results to scan_results.txt"
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="Save results to scan_results.json"
    )

    return parser.parse_args()


# Main

def main():

    args = get_arguments()

    banner()

    if args.target:

        target_input = args.target

    else:

        target_input = input(
            f"{CYAN}"
            f"Target IP / Hostname: "
            f"{RESET}"
        ).strip()

    if not target_input:

        print(
            f"{RED}"
            f"[!] Target cannot be empty."
            f"{RESET}"
        )

        sys.exit(1)

    ip = resolve_target(
        target_input
    )

    if args.ports:

        try:

            start_port, end_port = \
                parse_port_range(
                    args.ports
                )

        except ValueError:

            print(
                f"{RED}"
                f"[!] Invalid port range."
                f"{RESET}"
            )

            sys.exit(1)

    else:

        start_port, end_port = \
            get_port_range()

    if args.mode:

        mode = args.mode

    else:

        mode = select_mode()

    print(
        f"""
{BLUE}{BOLD}
Target      : {WHITE}{target_input}
{BLUE}IP Address  : {WHITE}{ip}
{BLUE}Port Range  : {WHITE}{start_port}-{end_port}
{BLUE}Scan Mode   : {WHITE}{mode}
{BLUE}Started     : {WHITE}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
{RESET}
"""
    )

    all_results = []

    if mode == "1" or mode == "tcp":

        results = tcp_scan(
            ip,
            start_port,
            end_port,
            timeout=0.5,
            workers=args.workers
        )

        all_results.extend(results)

    elif mode == "2" or mode == "fast":

        results = tcp_scan(
            ip,
            start_port,
            end_port,
            timeout=0.15,
            workers=args.workers
        )

        all_results.extend(results)

    elif mode == "3" or mode == "udp":

        results = udp_scan(
            ip,
            start_port,
            end_port
        )

        all_results.extend(results)

    elif mode == "4" or mode == "both":

        tcp_results = tcp_scan(
            ip,
            start_port,
            end_port,
            timeout=args.timeout,
            workers=args.workers
        )

        all_results.extend(
            tcp_results
        )

        udp_results = udp_scan(
            ip,
            start_port,
            end_port
        )

        all_results.extend(
            udp_results
        )

    if args.txt:

        save_txt(
            "scan_results.txt",
            target_input,
            ip,
            start_port,
            end_port,
            mode,
            all_results
        )

    if args.json:

        save_json(
            "scan_results.json",
            target_input,
            ip,
            start_port,
            end_port,
            mode,
            all_results
        )

    tcp_open = sum(
        1
        for r in all_results
        if r["protocol"] == "TCP"
        and r["state"] == "open"
    )

    udp_open = sum(
        1
        for r in all_results
        if r["protocol"] == "UDP"
        and r["state"] == "open"
    )

    udp_filtered = sum(
        1
        for r in all_results
        if r["protocol"] == "UDP"
        and r["state"] == "open|filtered"
    )

    print(
        f"""
{CYAN}{BOLD}
╔════════════════════════════════════════╗
║             SCAN SUMMARY              ║
╚════════════════════════════════════════╝
{RESET}
{GREEN}[+] TCP Open          : {tcp_open}{RESET}
{GREEN}[+] UDP Open          : {udp_open}{RESET}
{YELLOW}[?] UDP Open|Filtered : {udp_filtered}{RESET}

{GREEN}{BOLD}[✓] Scan completed.{RESET}
"""
    )


# Start

if __name__ == "__main__":

    try:

        main()

    except KeyboardInterrupt:

        print(
            f"\n\n{RED}{BOLD}"
            f"[!] Scan interrupted by user."
            f"{RESET}"
        )

        sys.exit(0)