import nmap

def scan_network(target):
    scanner = nmap.PortScanner()
    print(f"Scanning {target}...")
    scanner.scan(target, '1-1024', '-sV')

    for host in scanner.all_hosts():
        print(f"\nHost: {host} ({scanner[host].hostname()})")
        print(f"State: {scanner[host].state()}")

        for protocol in scanner[host].all_protocols():
            print(f"\nProtocol: {protocol}")
            ports = scanner[host][protocol].keys()
            for port in sorted(ports):
                print(f"Port: {port}\tState: {scanner[host][protocol][port]['state']}")

# Example usage
scan_network('192.168.1.0/24')
