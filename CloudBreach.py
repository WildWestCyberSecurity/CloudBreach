import asyncio
import ssl
import socket
import logging
import argparse
import hashlib
import random
import requests
from aiohttp import ClientSession, ClientTimeout, TCPConnector
from colorama import Fore, Style, init
from tqdm import tqdm
import os

# Initialize colorama
init(autoreset=True)

# Setup logging
logging.basicConfig(filename='cloudflare_bypass.log', level=logging.DEBUG,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Check for optional dependencies
try:
    import whois
    import ipwhois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False
    print(f"{Fore.YELLOW}whois or ipwhois module not found. WHOIS lookup will be skipped.")
    print("To enable WHOIS lookup, install them with: pip install python-whois ipwhois")

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False
    print(f"{Fore.YELLOW}dnspython module not found. DNS resolution will be skipped.")
    print("To enable DNS resolution, install it with: pip install dnspython")

# Initialize WHOIS cache
whois_cache = {}

# Custom SSL Context Configuration
def create_ssl_context(verify_ssl):
    if verify_ssl:
        return ssl.create_default_context()
    else:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context

# Fetch historical DNS records using SecurityTrails API
def fetch_historical_records(domain, record_type, api_key):
    url = f"https://api.securitytrails.com/v1/history/{domain}/dns/{record_type}"
    headers = {
        "accept": "application/json",
        "apikey": api_key
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Failed to retrieve {record_type} records: {response.status_code} - {response.text}")
        return None

# Extract IPs from the SecurityTrails API response
def extract_ips(data):
    ips = set()
    if "records" in data:
        for record in data["records"]:
            for value in record.get("values", []):
                ip = value.get("ip")
                if ip:
                    ips.add(ip)
    return ips

# Save IPs to a file
def save_ips_to_file(ips, filename):
    with open(filename, 'w') as f:
        for ip in sorted(ips):
            f.write(f"{ip}\n")

# Function to analyze responses
async def analyze_response(ip, response, domain):
    score = 0
    headers = response.headers
    
    if 'Server' in headers and 'cloudflare' not in headers['Server'].lower():
        score += 10
    if 'X-Powered-By' in headers:
        score += 5
    if domain in await response.text():
        score += 5
    if response.status == 200:
        score += 10
    
    return score

# Fetch content from a URL
async def fetch_content(session, url):
    try:
        async with session.get(url) as response:
            return await response.text()
    except Exception as e:
        logging.debug(f"Failed to fetch content from {url}: {e}")
        return None

# Fetch SSL certificate
async def fetch_ssl_cert(ip, domain, verify_ssl):
    try:
        context = create_ssl_context(verify_ssl)
        conn = asyncio.open_connection(ip, 443, ssl=context, server_hostname=domain)
        reader, writer = await asyncio.wait_for(conn, timeout=5)
        cert = writer.get_extra_info('peercert')
        writer.close()
        await writer.wait_closed()
        return cert
    except Exception as e:
        logging.debug(f"SSL cert fetch failed for {ip}: {e}")
        return None

# Check if SSL certificate matches the domain
def check_ssl_cert_match(cert, domain):
    common_name = cert.get('subject', ((('commonName', ''),),))[0][0][1]
    alt_names = cert.get('subjectAltName', [])
    return domain in common_name or domain in [name for _, name in alt_names]

# Check if content matches between the Cloudflare and direct IP
async def check_content_match(session, domain, ip):
    original_url = f"https://{domain}"
    direct_url = f"http://{ip}"
    
    original_content = await fetch_content(session, original_url)
    direct_content = await fetch_content(session, direct_url)
    
    if original_content and direct_content:
        original_hash = hashlib.sha256(original_content.encode('utf-8')).hexdigest()
        direct_hash = hashlib.sha256(direct_content.encode('utf-8')).hexdigest()
        return original_hash == direct_hash
    
    return False

# WHOIS lookup with caching
def ip_whois_lookup(ip):
    if not WHOIS_AVAILABLE:
        return None
    if ip in whois_cache:
        return whois_cache[ip]
    try:
        obj = ipwhois.IPWhois(ip)
        results = obj.lookup_rdap(depth=1)
        org_name = None
        
        for entity in results.get('entities', []):
            entity_data = results.get('objects', {}).get(entity, {})
            if 'roles' in entity_data:
                if 'registrant' in entity_data['roles'] or 'organization' in entity_data['roles']:
                    org_name = entity_data.get('contact', {}).get('name')
                    if org_name:
                        break
        
        if not org_name:
            org_name = results.get('network', {}).get('name')
        
        whois_cache[ip] = org_name
        return org_name
    except Exception as e:
        logging.error(f"IP WHOIS lookup failed for {ip}: {e}")
        return None

# Asynchronous request function
async def fetch(session, url, ip, domain, verify_ssl, ssl_check_enabled):
    headers = {
        'Host': domain,
        'User-Agent': random.choice(USER_AGENTS),
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate, br',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1'
    }
    timeout = ClientTimeout(total=10)
    try:
        async with session.get(url, headers=headers, timeout=timeout) as response:
            score = await analyze_response(ip, response, domain)
            
            if response.status == 200:
                if ssl_check_enabled:
                    ssl_cert = await fetch_ssl_cert(ip, domain, verify_ssl)
                    if ssl_cert and check_ssl_cert_match(ssl_cert, domain):
                        score += 10
                if await check_content_match(session, domain, ip):
                    score += 20
            
            return ip, score, response.status
    except Exception as e:
        logging.debug(f"Request to {ip} failed: {e}")
        return ip, 0, None

# Color-code the score
def color_code_score(score):
    if score == 60:
        return f"{Fore.GREEN}{score} - Definite Origin{Style.RESET_ALL}"
    elif 50 <= score < 60:
        return f"{Fore.LIGHTGREEN_EX}{score} - Very Likely Origin{Style.RESET_ALL}"
    elif 30 <= score < 50:
        return f"{Fore.YELLOW}{score} - Probable Origin{Style.RESET_ALL}"
    elif 20 <= score < 30:
        return f"{Fore.MAGENTA}{score} - Possible Origin{Style.RESET_ALL}"
    else:
        return f"{Fore.RED}{score} - Unlikely Origin{Style.RESET_ALL}"

# Asynchronous DNS resolution
async def resolve_domain(domain):
    if not DNS_AVAILABLE:
        print(f"{Fore.RED}DNS resolution is not available. Please provide IPs using the -L option.")
        return []
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ['8.8.8.8', '1.1.1.1']
        answers = await asyncio.gather(*[resolver.resolve(domain, 'A'), resolver.resolve(domain, 'AAAA')])
        ipv4_addresses = [str(rdata) for rdata in answers[0]]
        ipv6_addresses = [str(rdata) for rdata in answers[1]]
        return ipv4_addresses + ipv6_addresses
    except Exception as e:
        logging.error(f"DNS resolution failed for {domain}: {e}")
        return []

# Read IPs from file
def read_ips_from_file(filename):
    if os.path.exists(filename):
        with open(filename, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    return []

# Main async function
async def main(domain, ip_list_file, output_file, verify_ssl, ssl_check_enabled, api_key):
    ips = set()

    # Fetch IPs using SecurityTrails API if --api flag is used
    if api_key:
        print(f"{Fore.YELLOW}Fetching IPs from SecurityTrails API...")
        data_a = fetch_historical_records(domain, "a", api_key)
        if data_a:
            ips.update(extract_ips(data_a))
        data_aaaa = fetch_historical_records(domain, "aaaa", api_key)
        if data_aaaa:
            ips.update(extract_ips(data_aaaa))
        if not ips:
            print(f"{Fore.RED}No IPs found using SecurityTrails API.")
    if ip_list_file:
        ips.update(read_ips_from_file(ip_list_file))
        if not ips:
            print(f"{Fore.RED}No IPs found in the specified file: {ip_list_file}")
            return

    if not ips:
        print(f"{Fore.RED}No IPs found from either the API or the IP list.")
        return
    
    print(f"{Fore.CYAN}Testing {len(ips)} IP addresses.")
    
    connector = TCPConnector(ssl=False)
    async with ClientSession(connector=connector) as session:
        tasks = []
        for ip in ips:
            url_http = f'http://{ip}/'
            url_https = f'https://{ip}/'
            tasks.append(fetch(session, url_http, ip, domain, verify_ssl, ssl_check_enabled))
            tasks.append(fetch(session, url_https, ip, domain, verify_ssl, ssl_check_enabled))
        
        results = []
        for task in tqdm(asyncio.as_completed(tasks), total=len(tasks), desc="Checking IPs"):
            results.append(await task)
    
    valid_results = [result for result in results if result[1] > 0]
    valid_results.sort(key=lambda x: x[1], reverse=True)
    
    print(f"\n{Fore.GREEN}Valid IPs found:")
    valid_ips = []
    for result in valid_results:
        ip, score, status = result
        org = ip_whois_lookup(ip)
        if ssl_check_enabled:
            ssl_cert = await fetch_ssl_cert(ip, domain, verify_ssl)
            ssl_valid = check_ssl_cert_match(ssl_cert, domain) if ssl_cert else False
        else:
            ssl_valid = 'N/A'
        valid_ips.append(ip)
        colored_score = color_code_score(score)
        print(f"{Fore.CYAN}{ip} - Score: {colored_score}, Status: {status}, SSL Valid: {'Yes' if ssl_valid == True else ssl_valid}")
        if org:
            print(f"  Organization: {org}")
        print()

    if output_file:
        with open(output_file, 'w') as f:
            for ip in valid_ips:
                f.write(f"{ip}\n")
        print(f"{Fore.GREEN}Valid IPs have been written to {output_file}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description=(
            "Cloudflare bypass script: A tool designed to help identify potential origin IPs "
            "behind a Cloudflare-protected domain by analyzing HTTP responses and performing WHOIS lookups. "
            "The script assigns a 'score' to each IP based on several factors, such as the presence or absence "
            "of certain HTTP headers and the response status. Higher scores indicate a higher likelihood "
            "that the IP is the actual origin server."
        )
    )
    parser.add_argument(
        "-d", "--domain", 
        required=True, 
        help="The domain you want to test against. This is the Cloudflare-protected domain."
    )
    parser.add_argument(
        "-L", "--ip-list", 
        help="Path to a file containing a list of IPs to check. Each IP should be on a new line."
    )
    parser.add_argument(
        "--api", 
        help="Specify SecurityTrails API key to fetch IPs."
    )
    parser.add_argument(
        "-o", "--output", 
        help="Specify an output file to save valid IPs (one per line)."
    )
    parser.add_argument(
        "--verify-ssl", 
        action='store_true', 
        help="Enable SSL certificate verification (default: False, skips SSL verification)."
    )
    parser.add_argument(
        "--ssl-check", 
        action='store_true', 
        help="Enable SSL certificate fetching and checking (default: False, skips SSL checks)."
    )

    args = parser.parse_args()

    USER_AGENTS = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Safari/605.1.15',
        'Mozilla/5.0 (iPhone; CPU iPhone OS 14_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Mobile/15E148 Safari/604.1'
    ]

    # Display scoring information at the start of the script
    print(f"{Fore.CYAN}Scoring Information:{Style.RESET_ALL}")
    print(f"{Fore.CYAN}-------------------{Style.RESET_ALL}")
    print(f"The script assigns a score to each IP based on the following criteria:\n")
    print(f"  {Fore.GREEN}+10 points{Style.RESET_ALL} if the '{Fore.YELLOW}Server{Style.RESET_ALL}' header is present and does not mention '{Fore.YELLOW}cloudflare{Style.RESET_ALL}'.")
    print(f"  {Fore.GREEN}+5 points{Style.RESET_ALL} if the '{Fore.YELLOW}X-Powered-By{Style.RESET_ALL}' header is present.")
    print(f"  {Fore.GREEN}+5 points{Style.RESET_ALL} if the domain is found within the response body.")
    print(f"  {Fore.GREEN}+10 points{Style.RESET_ALL} if the server returns a '{Fore.YELLOW}200 OK{Style.RESET_ALL}' status code.")
    print(f"  {Fore.GREEN}+10 points{Style.RESET_ALL} if the SSL certificate matches the domain's SSL certificate.")
    print(f"  {Fore.GREEN}+20 points{Style.RESET_ALL} if the content fetched from the IP matches the content served by the domain.\n")

    print(f"{Fore.CYAN}Score Interpretation:{Style.RESET_ALL}")
    print(f"{Fore.GREEN}  60 points: Definite Origin{Style.RESET_ALL} - The IP meets all criteria, making it almost certainly the origin server.")
    print(f"{Fore.LIGHTGREEN_EX}  50-59 points: Very Likely Origin{Style.RESET_ALL} - The IP is very likely the origin server, with high confidence.")
    print(f"{Fore.YELLOW}  30-49 points: Probable Origin{Style.RESET_ALL} - The IP has many signs of being the origin server but isn't definitive.")
    print(f"{Fore.MAGENTA}  20-29 points: Possible Origin{Style.RESET_ALL} - The IP could be the origin server, but there's significant doubt.")
    print(f"{Fore.RED}  Under 20 points: Unlikely Origin{Style.RESET_ALL} - The IP is unlikely to be the origin server.\n")

    print(f"{Fore.CYAN}Higher scores indicate a higher likelihood that the IP is the actual origin server.{Style.RESET_ALL}")
    print(f"{Fore.CYAN}This score helps prioritize IPs that are more likely to be of interest when trying to bypass Cloudflare.{Style.RESET_ALL}")

    asyncio.run(main(args.domain, args.ip_list, args.output, args.verify_ssl, args.ssl_check, args.api))
