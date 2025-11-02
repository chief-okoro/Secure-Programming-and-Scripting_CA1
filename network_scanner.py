# Ashley Okoro sba25350 


import socket
import sys
import argparse
import ipaddress
import threading
import time
from typing import List, Tuple, Dict, Optional
from datetime import datetime
from queue import Queue

# Optional nmap library import
try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False
    print("[INFO] python-nmap not installed. Using socket-based scanning only.")



# Most commonly scanned ports and their typical services
COMMON_PORTS = {
    20: "FTP-DATA",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    27017: "MongoDB",
}

# Extended port list for comprehensive scanning
EXTENDED_PORTS = list(range(1, 1025))  # Well-known ports

class NetworkScanner:
   

    def __init__(self, targets: List[str], ports: List[int],
                 scan_udp: bool = False, service_detection: bool = False,
                 threads: int = 100):
       
        self.targets = targets
        self.ports = ports
        self.scan_udp = scan_udp
        self.service_detection = service_detection
        self.threads = threads

        # Results storage
        self.results = {}
        self.scan_queue = Queue()
        self.lock = threading.Lock()

    def tcp_scan(self, ip: str, port: int, timeout: float = 1.0) -> bool:
 
        try:
            # Create TCP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)

            # Attempt connection
            result = sock.connect_ex((ip, port))

            sock.close()

            # Result code 0 means connection succeeded
            return result == 0

        except socket.error:
            return False
        except Exception:
            return False

    def udp_scan(self, ip: str, port: int, timeout: float = 2.0) -> bool:
     
        try:
            # Create UDP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)

            # Send empty UDP packet
            sock.sendto(b'', (ip, port))

            try:
                # Try to receive response
                data, addr = sock.recvfrom(1024)
                sock.close()
                return True  # Received response - port is open
            except socket.timeout:
                # No response - likely open or filtered
                sock.close()
                return True

        except socket.error as e:
            # ICMP port unreachable received - port is closed
            if "forcibly closed" in str(e) or "unreachable" in str(e):
                return False
            return True  # Assume open/filtered if uncertain
        except Exception:
            return False

    def grab_banner(self, ip: str, port: int, timeout: float = 2.0) -> Optional[str]:
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((ip, port))

            # Try to receive banner (some services send it immediately)
            try:
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                if banner:
                    sock.close()
                    return banner
            except socket.timeout:
                pass

            # Send generic HTTP request for web servers
            if port in [80, 8080, 443, 8443]:
                try:
                    sock.send(b'GET / HTTP/1.1\r\nHost: ' + ip.encode() + b'\r\n\r\n')
                    response = sock.recv(1024).decode('utf-8', errors='ignore')
                    # Extract server header
                    for line in response.split('\n'):
                        if line.lower().startswith('server:'):
                            sock.close()
                            return line.split(':', 1)[1].strip()
                except:
                    pass

            # Send SMTP EHLO for mail servers
            if port in [25, 587]:
                try:
                    sock.recv(1024)  # Read initial banner
                    sock.send(b'EHLO scanner\r\n')
                    response = sock.recv(1024).decode('utf-8', errors='ignore')
                    sock.close()
                    return response.split('\n')[0].strip()
                except:
                    pass

            sock.close()
            return None

        except Exception:
            return None

    def scan_port(self, ip: str, port: int, protocol: str = 'tcp') -> Dict:
       
        result = {
            'port': port,
            'protocol': protocol,
            'state': 'closed',
            'service': COMMON_PORTS.get(port, 'unknown'),
            'banner': None
        }

        # Perform appropriate scan based on protocol
        if protocol == 'tcp':
            is_open = self.tcp_scan(ip, port)
        else:
            is_open = self.udp_scan(ip, port)

        if is_open:
            result['state'] = 'open'

            # Attempt service identification if enabled
            if self.service_detection and protocol == 'tcp':
                banner = self.grab_banner(ip, port)
                if banner:
                    result['banner'] = banner[:100]  # Truncate long banners

        return result

    def worker(self):
       
        while True:
            try:
                # Get scan job from queue
                ip, port, protocol = self.scan_queue.get(timeout=1)

                # Perform scan
                result = self.scan_port(ip, port, protocol)

                # Store result if port is open
                if result['state'] == 'open':
                    with self.lock:
                        if ip not in self.results:
                            self.results[ip] = []
                        self.results[ip].append(result)

                        # Print result immediately
                        service_info = f"{result['service']}"
                        if result['banner']:
                            service_info += f" - {result['banner']}"

                        print(f"[+] {ip}:{port}/{protocol} - OPEN - {service_info}")

                # Mark job as complete
                self.scan_queue.task_done()

            except:
                break

    def scan(self) -> Dict:
       
        print(f"Network Port Scanner")
        print(f"Targets: {len(self.targets)} host(s)")
        print(f"Ports: {len(self.ports)} port(s)")
        print(f"Protocols: TCP" + (" + UDP" if self.scan_udp else ""))
        print(f"Service Detection: {'Enabled' if self.service_detection else 'Disabled'}")
        print(f"Threads: {self.threads}")
        print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

        # Populate scan queue
        for ip in self.targets:
            for port in self.ports:
                # Add TCP scan job
                self.scan_queue.put((ip, port, 'tcp'))

                # Add UDP scan job if enabled
                if self.scan_udp:
                    self.scan_queue.put((ip, port, 'udp'))

        total_scans = self.scan_queue.qsize()
        print(f"[*] Total scan operations: {total_scans}\n")

        # Start worker threads
        threads = []
        for i in range(min(self.threads, total_scans)):
            t = threading.Thread(target=self.worker, daemon=True)
            t.start()
            threads.append(t)

        # Wait for all scans to complete
        start_time = time.time()
        self.scan_queue.join()
        elapsed_time = time.time() - start_time

        # Print summary
        print(f"Scan Complete")
        print(f"Duration: {elapsed_time:.2f} seconds")
        print(f"Hosts with open ports: {len(self.results)}")

        total_open_ports = sum(len(ports) for ports in self.results.values())
        print(f"Total open ports found: {total_open_ports}")

        return self.results

    def print_detailed_results(self):
    
        if not self.results:
            print("\n[!] No open ports found.")
            return

        print(f"Detailed Results")

        for ip in sorted(self.results.keys()):
            print(f"Host: {ip}")
            print(f"{'-'*70}")

            # Sort ports numerically
            ports_info = sorted(self.results[ip], key=lambda x: x['port'])

            for port_info in ports_info:
                port = port_info['port']
                protocol = port_info['protocol']
                service = port_info['service']
                banner = port_info['banner']

                print(f"  {port}/{protocol:<6} {service:<20}", end='')

                if banner:
                    print(f" [{banner}]")
                else:
                    print()

            print()

    def save_results(self, filename: str = None):
       
        if filename is None:
            filename = f"scan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

        try:
            with open(filename, 'w') as f:
                f.write("="*70 + "\n")
                f.write("Network Scan Results\n")
                f.write("="*70 + "\n")
                f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Targets Scanned: {len(self.targets)}\n")
                f.write(f"Ports Scanned: {len(self.ports)}\n")
                f.write(f"Hosts with Open Ports: {len(self.results)}\n")
                f.write("="*70 + "\n\n")

                for ip in sorted(self.results.keys()):
                    f.write(f"Host: {ip}\n")
                    f.write("-"*70 + "\n")

                    ports_info = sorted(self.results[ip], key=lambda x: x['port'])

                    for port_info in ports_info:
                        port = port_info['port']
                        protocol = port_info['protocol']
                        service = port_info['service']
                        banner = port_info['banner'] or 'N/A'

                        f.write(f"  Port: {port}/{protocol}\n")
                        f.write(f"  Service: {service}\n")
                        f.write(f"  Banner: {banner}\n")
                        f.write("\n")

                    f.write("\n")

            print(f"[+] Results saved to: {filename}")

        except IOError as e:
            print(f"[ERROR] Failed to save results: {e}")



def parse_ip_range(ip_range: str) -> List[str]:

    ip_list = []

    # Check for CIDR notation
    if '/' in ip_range:
        try:
            network = ipaddress.ip_network(ip_range, strict=False)
            ip_list = [str(ip) for ip in network.hosts()]
        except ValueError as e:
            raise ValueError(f"Invalid CIDR notation: {e}")

    # Check for range notation (e.g., 192.168.1.1-192.168.1.254)
    elif '-' in ip_range:
        try:
            start_ip, end_ip = ip_range.split('-')
            start_ip = start_ip.strip()
            end_ip = end_ip.strip()

            # If end_ip is just a number, append it to start_ip prefix
            if '.' not in end_ip:
                prefix = '.'.join(start_ip.split('.')[:-1])
                end_ip = f"{prefix}.{end_ip}"

            start = ipaddress.IPv4Address(start_ip)
            end = ipaddress.IPv4Address(end_ip)

            # Generate IP range
            current = start
            while current <= end:
                ip_list.append(str(current))
                current += 1

        except ValueError as e:
            raise ValueError(f"Invalid IP range: {e}")

    # Single IP address
    else:
        try:
            ipaddress.IPv4Address(ip_range)
            ip_list = [ip_range]
        except ValueError:
            raise ValueError(f"Invalid IP address: {ip_range}")

    return ip_list


def parse_ports(port_spec: str) -> List[int]:
  
    ports = []

    for part in port_spec.split(','):
        part = part.strip()

        # Port range
        if '-' in part:
            try:
                start, end = map(int, part.split('-'))
                if start < 1 or end > 65535 or start > end:
                    raise ValueError(f"Invalid port range: {part}")
                ports.extend(range(start, end + 1))
            except ValueError as e:
                raise ValueError(f"Invalid port range '{part}': {e}")

        # Single port
        else:
            try:
                port = int(part)
                if port < 1 or port > 65535:
                    raise ValueError(f"Port out of range: {port}")
                ports.append(port)
            except ValueError as e:
                raise ValueError(f"Invalid port '{part}': {e}")

    return sorted(list(set(ports)))  # Remove duplicates and sort


def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(
        description='Network Port Scanner - Defensive Security Tool',
        epilog='Example: python network_scanner.py --target 192.168.1.1 --ports 1-1024',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument(
        '--target', '-t',
        required=True,
        help='Target IP address or range (e.g., 192.168.1.1 or 192.168.1.0/24 or 192.168.1.1-192.168.1.254)'
    )

    parser.add_argument(
        '--ports', '-p',
        help='Ports to scan (e.g., 22,80,443 or 1-1024). Use --common for common ports.'
    )

    parser.add_argument(
        '--common',
        action='store_true',
        help='Scan common ports (FTP, SSH, HTTP, HTTPS, etc.)'
    )

    parser.add_argument(
        '--all',
        action='store_true',
        help='Scan all well-known ports (1-1024) - WARNING: Slow!'
    )

    parser.add_argument(
        '--udp',
        action='store_true',
        help='Enable UDP scanning in addition to TCP (slower and less reliable)'
    )

    parser.add_argument(
        '--services',
        action='store_true',
        help='Attempt service identification via banner grabbing'
    )

    parser.add_argument(
        '--threads',
        type=int,
        default=100,
        help='Number of concurrent scanning threads (default: 100)'
    )

    parser.add_argument(
        '--output', '-o',
        help='Save results to specified file'
    )

    args = parser.parse_args()

    # Validate and parse targets
    try:
        targets = parse_ip_range(args.target)
        print(f"[*] Parsed {len(targets)} target(s)")
    except ValueError as e:
        print(f"[ERROR] {e}")
        sys.exit(1)

    # Determine which ports to scan
    if args.all:
        ports = EXTENDED_PORTS
        print(f"[*] Scanning all well-known ports (1-1024)")
    elif args.common:
        ports = sorted(COMMON_PORTS.keys())
        print(f"[*] Scanning common ports")
    elif args.ports:
        try:
            ports = parse_ports(args.ports)
            print(f"[*] Scanning {len(ports)} specified port(s)")
        except ValueError as e:
            print(f"[ERROR] {e}")
            sys.exit(1)
    else:
        # Default to common ports
        ports = sorted(COMMON_PORTS.keys())
        print(f"[*] No ports specified, using common ports")

    # Warning for large scans
    total_operations = len(targets) * len(ports) * (2 if args.udp else 1)
    if total_operations > 10000:
        print(f"[WARNING] This may take a considerable amount of time and generate network traffic.")
        response = input("Continue? (yes/no): ")
        if response.lower() not in ['yes', 'y']:
            print("[*] Scan cancelled.")
            sys.exit(0)

    try:
        # Initialize and run scanner
        scanner = NetworkScanner(
            targets=targets,
            ports=ports,
            scan_udp=args.udp,
            service_detection=args.services,
            threads=args.threads
        )

        # Execute scan
        results = scanner.scan()

        # Display detailed results
        scanner.print_detailed_results()

        # Save results if requested
        if args.output:
            scanner.save_results(args.output)

    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")
        sys.exit(130)
    except Exception as e:
        print(f"[ERROR] Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
