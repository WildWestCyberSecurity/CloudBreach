# 🌩️ CloudBreach.py - Cloudflare Origin IP Detection and Bypass Tool

## 🚀 Overview
`CloudBreach.py` is a powerful Python tool designed to help identify origin IP addresses behind Cloudflare-protected domains. By analyzing HTTP responses, performing WHOIS lookups, and checking SSL certificates, this script assigns a "score" to each IP to determine the likelihood of it being the actual origin server.

## 🛠️ Features
- **Asynchronous Operations**: Utilizes Python's asyncio for fast, concurrent HTTP requests.
- **SecurityTrails API Integration**: Fetches historical DNS records to uncover hidden IPs.
- **WHOIS Lookup**: Identifies organizations associated with IP addresses.
- **SSL Certificate Matching**: Compares SSL certificates to validate origin servers.
- **Content Hashing**: Ensures content consistency between Cloudflare and direct IP access.
- **Color-Coded Scoring**: Easy interpretation of IP scores based on various checks.

## 📋 Requirements

Make sure to install the required Python packages:

```
pip install -r requirements.txt
```

Here’s what your `requirements.txt` should include:

```
aiohttp
argparse
asyncio
colorama
dnspython
ipwhois
requests
tqdm
whois
```

## 🚀 Usage

Run the script with the following command:

```
python CloudBreach.py -d <domain> [options]
```

### Example:
```
python CloudBreach.py -d example.com --api YOUR_SECURITYTRAILS_API_KEY -o valid_ips.txt --ssl-check
```

### Arguments:
- `-d`, `--domain`: The domain to test against (required).
- `-L`, `--ip-list`: Path to a file containing a list of IPs to check.
- `--api`: Specify your SecurityTrails API key to fetch IPs.
- `-o`, `--output`: Output file to save valid IPs.
- `--verify-ssl`: Enable SSL certificate verification.
- `--ssl-check`: Enable SSL certificate fetching and checking.

### Scoring Information:
- **+10 points**: `Server` header is present and does not mention `cloudflare`.
- **+5 points**: `X-Powered-By` header is present.
- **+5 points**: Domain is found within the response body.
- **+10 points**: Server returns a `200 OK` status code.
- **+10 points**: SSL certificate matches the domain's SSL certificate.
- **+20 points**: Content fetched from the IP matches the content served by the domain.

### Score Interpretation:
- **60 points**: Definite Origin - Almost certainly the origin server.
- **50-59 points**: Very Likely Origin - High confidence it’s the origin server.
- **30-49 points**: Probable Origin - Many signs of being the origin server.
- **20-29 points**: Possible Origin - Could be the origin server, but some doubt.
- **Under 20 points**: Unlikely Origin - Unlikely to be the origin server.

## 📄 License
This project is licensed under the MIT License.

## 💬 Contributing
Contributions are welcome! Please feel free to submit a Pull Request.

## 🔗 References
- [aiohttp Documentation](https://docs.aiohttp.org/)
- [SecurityTrails API](https://securitytrails.com/corp/apidocs)

Enjoy uncovering the hidden IPs! 🎉
