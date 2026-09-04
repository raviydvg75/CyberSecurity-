# 🔎 Python Port Scanner

A lightweight **TCP/UDP port scanner built from scratch in Python** using the standard `socket` library.

The project demonstrates practical understanding of **network programming, TCP/UDP communication, multithreading, port scanning, service detection, CLI tools, and result reporting**.

> ⚠️ **Disclaimer:** This tool is intended for educational purposes and authorized security testing only. Scan only systems that you own or have explicit permission to test.

---

## ✨ Features

* 🔌 TCP Connect Port Scanning
* 📡 UDP Port Scanning
* ⚡ Multithreaded TCP scanning
* 🚀 Fast TCP scanning mode
* 🔄 TCP + UDP combined scanning
* 🧭 Hostname/IP address resolution
* 🔍 Basic service identification
* 📊 Real-time progress bar
* 🎨 Colored terminal interface
* 💾 TXT result export
* 📄 JSON result export
* 🖥️ Interactive scanning mode
* ⌨️ Command-line arguments
* ❌ Input validation
* 🛑 Keyboard interrupt handling

---

## 🛠️ Technologies

* Python 3
* Socket programming
* TCP/IP
* UDP
* Multithreading
* `argparse`
* `json`
* `concurrent.futures`

No Nmap or Scapy is used for the core scanning functionality.

---

## 📸 Screenshot

![Python Port Scanner](screenshots/scanner.png)

---

## 📁 Project Structure

```text
python-port-scanner/
│
├── port_scanner.py
├── README.md
├── LICENSE
├── .gitignore
│
└── screenshots/
    └── scanner.png
```

---

## ⚙️ Requirements

Python 3.8 or newer is recommended.

Check your Python version:

```bash
python3 --version
```

Clone the repository:

```bash
git clone https://github.com/YOUR_USERNAME/python-port-scanner.git
```

Enter the project:

```bash
cd python-port-scanner
```

Run:

```bash
python3 port_scanner.py
```

---

## 🚀 Interactive Usage

Run the scanner:

```bash
python3 port_scanner.py
```

Enter the target:

```text
Target IP / Hostname:
```

Example:

```text
127.0.0.1
```

Enter the port range:

```text
Port range (example: 1-1024):
```

Example:

```text
1-1024
```

Select a scan mode:

```text
Select Scan Mode
================

[1] Normal TCP Scan
[2] Fast TCP Scan
[3] UDP Scan
[4] TCP + UDP Scan
```

---

## 🧪 Command-Line Usage

### TCP scan

```bash
python3 port_scanner.py 127.0.0.1 -p 1-1024 -m tcp
```

### Fast TCP scan

```bash
python3 port_scanner.py 127.0.0.1 -p 1-1024 -m fast
```

### UDP scan

```bash
python3 port_scanner.py 127.0.0.1 -p 1-100 -m udp
```

### TCP + UDP scan

```bash
python3 port_scanner.py 127.0.0.1 -p 1-100 -m both
```

---

## ⚡ Multithreading

TCP scanning uses Python's `ThreadPoolExecutor` to scan multiple ports concurrently.

Default:

```text
100 workers
```

Change the number of workers:

```bash
python3 port_scanner.py 127.0.0.1 -p 1-1024 -m tcp -w 50
```

---

## ⏱️ Timeout

Configure TCP timeout with:

```bash
-t
```

Example:

```bash
python3 port_scanner.py 127.0.0.1 -p 1-1024 -m tcp -t 1
```

The default TCP timeout is `0.5` seconds.

Fast mode uses a shorter timeout.

> A shorter timeout can improve speed but may miss ports on slow or high-latency systems.

---

## 💾 Saving Results

### TXT

```bash
python3 port_scanner.py 127.0.0.1 -p 1-1024 -m tcp --txt
```

Creates:

```text
scan_results.txt
```

### JSON

```bash
python3 port_scanner.py 127.0.0.1 -p 1-1024 -m tcp --json
```

Creates:

```text
scan_results.json
```

### Both

```bash
python3 port_scanner.py 127.0.0.1 -p 1-1024 -m tcp --txt --json
```

---

## 🆘 Help

```bash
python3 port_scanner.py --help
```

Available modes:

```text
tcp
fast
udp
both
```

---

## 🔬 How It Works

### TCP Scanning

The scanner creates a TCP socket:

```python
socket.socket(
    socket.AF_INET,
    socket.SOCK_STREAM
)
```

It then attempts to connect to the target port using:

```python
connect_ex()
```

If the connection succeeds, the port is reported as:

```text
OPEN
```

### UDP Scanning

UDP scanning uses:

```python
socket.socket(
    socket.AF_INET,
    socket.SOCK_DGRAM
)
```

The scanner sends a UDP packet and waits for a response.

Because UDP timeouts are ambiguous, a timeout is reported as:

```text
OPEN|FILTERED
```

### Service Detection

The scanner uses Python's built-in:

```python
socket.getservbyport()
```

Example:

```text
TCP  22    OPEN    ssh
TCP  80    OPEN    http
TCP  443   OPEN    https
```

This is basic port/service mapping rather than full application fingerprinting.

---

## 📊 Example Output

```text
Target      : 127.0.0.1
IP Address  : 127.0.0.1
Port Range  : 1-1024
Scan Mode   : tcp

[*] TCP Connect Scan
[*] Threads : 100

[+] TCP 22     OPEN  ssh
[+] TCP 80     OPEN  http

[███████████████████████████████████] 100.00% (1024/1024)

╔════════════════════════════════════════╗
║             SCAN SUMMARY              ║
╚════════════════════════════════════════╝

[+] TCP Open          : 2
[+] UDP Open          : 0
[?] UDP Open|Filtered : 0

[✓] Scan completed.
```

---

## 🧠 What I Learned

This project helped me practice:

* Python socket programming
* TCP/IP fundamentals
* UDP communication
* Port scanning concepts
* Network service identification
* Multithreading
* Exception handling
* CLI application development
* JSON handling
* File handling
* Terminal UI development
* Cybersecurity reconnaissance concepts

---

## 🔮 Future Improvements

* [ ] TCP service/banner grabbing
* [ ] Improved UDP detection
* [ ] Concurrent UDP scanning
* [ ] Better scan statistics
* [ ] Configurable output filenames
* [ ] CSV export
* [ ] Logging support
* [ ] Unit tests
* [ ] Configuration file support
* [ ] IPv6 support
* [ ] Better service fingerprinting
* [ ] GitHub Actions

---

## ⚠️ Legal & Ethical Use

This project is intended for:

* Cybersecurity education
* Networking education
* CTFs
* Personal labs
* Authorized penetration testing

**Only scan systems that you own or have explicit permission to test.**

The developer is not responsible for misuse of this software.

---

## 👨‍💻 Author

**Rabi Bhushan Yadav**

Computer Engineering Student
Cybersecurity & Penetration Testing Enthusiast

---

## ⭐ Support

If this project helped you learn Python networking or cybersecurity, consider giving the repository a ⭐ on GitHub.

---

## 📜 License

This project is licensed under the **MIT License**.
