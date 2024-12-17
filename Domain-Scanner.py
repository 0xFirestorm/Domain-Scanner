import whois
import dns.resolver
import socket
import requests
import ssl
import OpenSSL
from dns.exception import DNSException
from dns.query import xfr
from dns.zone import from_xfr
import itertools

def print_ascii_art():
    print(r"""
	(  _ \(  _  )(  \/  )  /__\  (_  _)( \( )  / __) / __)  /__\  ( \( )( \( )( ___)(  _ \
	 )(_) ))(_)(  )    (  /(__)\  _)(_  )  (   \__ \( (__  /(__)\  )  (  )  (  )__)  )   /
	(____/(_____)(_/\/\_)(__)(__)(____)(_)\_)  (___/ \___)(__)(__)(_)\_)(_)\_)(____)(_)\_)
    """)

def get_whois_info(domain):
    try:
        whois_data = whois.whois(domain)
        print("\n--- WHOIS Information ---\n")
        print(f"Domain Name: {whois_data.get('domain_name', 'N/A')}")
        print(f"Registrar: {whois_data.get('registrar', 'N/A')}")
        print(f"Creation Date: {whois_data.get('creation_date', 'N/A')}")
        print(f"Expiration Date: {whois_data.get('expiration_date', 'N/A')}")
        print(f"Name Servers: {', '.join(whois_data.get('name_servers', []))}")
        print(f"Registrant Country: {whois_data.get('country', 'N/A')}")
    except Exception as e:
        print(f"Error retrieving WHOIS information: {e}")

def get_dns_records(domain):
    print("\n--- DNS Records ---\n")
    try:
        for record_type in ['A', 'AAAA', 'MX', 'NS', 'CNAME']:
            answers = dns.resolver.resolve(domain, record_type, raise_on_no_answer=False)
            print(f"{record_type} Records:")
            for answer in answers:
                print(f"  - {answer}")
            print()
    except Exception as e:
        print(f"Error retrieving DNS records: {e}")

def scan_open_ports(domain):
    print("\n--- Open Port Scan ---\n")
    ports_to_check = [21, 22, 25, 53, 80, 110, 143, 443, 3389]
    try:
        ip = socket.gethostbyname(domain)
        print(f"Scanning IP: {ip}\n")
        for port in ports_to_check:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    print(f"Port {port} is open")
    except Exception as e:
        print(f"Error scanning ports: {e}")

def reverse_dns(ip):
    try:
        hostname = socket.gethostbyaddr(ip)
        print(f"\nHostname for IP {ip}: {hostname[0]}")
    except Exception as e:
        print(f"Error performing reverse DNS lookup: {e}")

def ssl_certificate_info(domain):
    try:
        conn = ssl.create_connection((domain, 443))
        context = ssl.create_default_context()
        with context.wrap_socket(conn, server_hostname=domain) as sock:
            cert = sock.getpeercert(True)
            x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert)
            print(f"Issuer: {x509.get_issuer()}")
            print(f"Subject: {x509.get_subject()}")
            print(f"Valid From: {x509.get_notBefore().decode('utf-8')}")
            print(f"Valid Until: {x509.get_notAfter().decode('utf-8')}")
    except Exception as e:
        print(f"Error retrieving SSL certificate: {e}")

def inspect_http_headers(domain):
    try:
        response = requests.get(f"http://{domain}")
        print("HTTP Headers:")
        for key, value in response.headers.items():
            print(f"{key}: {value}")
    except Exception as e:
        print(f"Error retrieving HTTP headers: {e}")

def subdomain_enumeration(domain):
    subdomains = ['www', 'mail', 'ftp', 'dev', 'test', 'blog']
    print("\n--- Subdomain Enumeration ---\n")
    for subdomain in subdomains:
        subdomain_url = f"{subdomain}.{domain}"
        try:
            ip = socket.gethostbyname(subdomain_url)
            print(f"Subdomain Found: {subdomain_url} ({ip})")
        except socket.gaierror:
            pass

def google_dork(domain):
    print("\n--- Google Dork ---\n")
    basic_dorks = [
        f"site:{domain}",
        f"site:{domain} intitle:index.of",
        f"site:{domain} filetype:pdf",
        f"site:{domain} admin login",
    ]
    
    advanced_dorks = [
        f"site:{domain} ext:sql | ext:db | ext:log",
        f"site:{domain} inurl:wp-admin | inurl:login",
        f"site:{domain} ext:php intitle:phpinfo",
        f"site:{domain} inurl:/config | inurl:/settings",
        f"site:{domain} ext:bak | ext:old | ext:backup",
        f"site:{domain} \"index of /\" +parent",
        f"site:{domain} \"credentials\" | \"password\"",
        f"site:{domain} intext:\"sql syntax error\"",
        f"site:{domain} ext:xml | ext:json | ext:env",
        f"site:{domain} intitle:\"login\" | inurl:\"auth\"",
    ]

    print("Perform the following Google Dork queries manually to uncover information:")
    
    print("\nBasic Dorks:")
    for dork in basic_dorks:
        print(f"  - {dork}")

    print("\nAdvanced Dorks:")
    for dork in advanced_dorks:
        print(f"  - {dork}")

def test_zone_transfer(domain):
    print("\n--- Zone Transfer Test ---\n")
    try:
        ns_records = dns.resolver.resolve(domain, 'NS')
        for ns in ns_records:
            print(f"Testing nameserver: {ns}")
            try:
                zone = from_xfr(xfr(str(ns), domain))
                if zone:
                    print(f"Zone Transfer Successful! Records from {ns}:\n")
                    for name, node in zone.nodes.items():
                        print(name.to_text())
                else:
                    print(f"Zone Transfer failed on {ns}")
            except Exception as e:
                print(f"Zone Transfer failed on {ns}: {e}")
    except DNSException as e:
        print(f"Error retrieving nameservers: {e}")

def directory_brute_force(domain):
    print("\n--- Directory Brute Force ---\n")
    directories = ['admin', 'login', 'test', 'backup', 'config', 'uploads']
    for directory in directories:
        url = f"http://{domain}/{directory}"
        try:
            response = requests.get(url, timeout=2)
            if response.status_code == 200:
                print(f"Found directory: {url}")
            else:
                print(f"No directory at: {url}")
        except requests.exceptions.RequestException:
            print(f"Failed to connect to {url}")

def main():
    print_ascii_art()
    print("Welcome to the Extended Domain Scanner Tool!")
    
    options = {
        "1": {"func": get_whois_info, "prompt": "Enter the domain to scan (e.g., example.com): "},
        "2": {"func": get_dns_records, "prompt": "Enter the domain to scan (e.g., example.com): "},
        "3": {"func": scan_open_ports, "prompt": "Enter the domain to scan (e.g., example.com): "},
        "4": {"func": reverse_dns, "prompt": "Enter the IP address for reverse DNS lookup: "},
        "5": {"func": ssl_certificate_info, "prompt": "Enter the domain to scan (e.g., example.com): "},
        "6": {"func": inspect_http_headers, "prompt": "Enter the domain to scan (e.g., example.com): "},
        "7": {"func": subdomain_enumeration, "prompt": "Enter the domain to scan (e.g., example.com): "},
        "8": {"func": google_dork, "prompt": "Enter the domain to scan (e.g., example.com): "},
        "9": {"func": test_zone_transfer, "prompt": "Enter the domain to scan (e.g., example.com): "},
        "10": {"func": directory_brute_force, "prompt": "Enter the domain to scan (e.g., example.com): "}
    }

    while True:
        print("\nMenu:")
        for key, option in options.items():
            print(f"[{key}] {option['func'].__name__.replace('_', ' ').title()}")
        print("[11] Exit\n")
        
        choice = input("Enter your choice: ")
        if choice == "11":
            print("\nThank you for using the Extended Domain Scanner Tool!")
            break
        elif choice in options:
            user_input = input(options[choice]["prompt"])
            options[choice]["func"](user_input)
        else:
            print("\nInvalid choice. Please try again.")

if __name__ == "__main__":
    main()
