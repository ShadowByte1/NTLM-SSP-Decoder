import requests
import argparse
from urllib.parse import urlparse
import os
import base64
import struct
from datetime import datetime, timedelta
from termcolor import colored

# A dictionary to map versions to OS names
version_mapping = {
    (6, 1): "Windows 7 / Windows Server 2008 R2",
    (6, 2): "Windows 8 / Windows Server 2012",
    (6, 3): "Windows 8.1 / Windows Server 2012 R2",
    (10, 0): "Windows 10 / Windows Server 2016/2019",
}

# List of common NTLM-authenticated paths to check
paths = [
    "/owa/",
    "/owa/auth.owa",
    "/Autodiscover/",
    "/Autodiscover/Autodiscover.xml",
    "/rpc/rpcproxy.dll"
]

# Function to check for NTLM disclosure for a specific path
def check_ntlm(domain, path):
    url = f"https://{domain}{path}"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Priority": "u=0, i",
        "Authorization": "NTLM TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAKAF1YAAAADw=="
    }

    try:
        # Send the GET request with a timeout of 10 seconds
        response = requests.get(url, headers=headers, timeout=10)

        # Check for the 'WWW-Authenticate' header in the response
        if 'WWW-Authenticate' in response.headers:
            auth_header = response.headers['WWW-Authenticate']
            if 'NTLM' in auth_header:
                ntlm_response = auth_header.split(",")[0].strip()  # Only the NTLM part
                print(colored(f"[+] NTLM Response Found for {domain}", "green"))
                decoded_ntlm_info = decode_ntlm(ntlm_response.split(' ')[1])
                generate_report(domain, url, ntlm_response, headers, decoded_ntlm_info)
                return True  # NTLM Response found, stop checking other paths
    except requests.exceptions.Timeout:
        print(colored(f"[!] Request timed out for {url} after 10 seconds", "yellow"))
    except Exception as e:
        print(colored(f"[!] Error with {url}: {e}", "yellow"))
    
    return False  # NTLM not found for this path

# NTLM decoder function
def decode_ntlm(ntlm_message):
    # Decode the base64-encoded NTLM message
    ntlm_bytes = base64.b64decode(ntlm_message)

    # NTLM Type 2 message structure
    signature = ntlm_bytes[:8].decode('ascii')
    if signature != 'NTLMSSP\x00':
        raise ValueError('Not an NTLM message')

    message_type = struct.unpack('<I', ntlm_bytes[8:12])[0]
    if message_type != 2:
        raise ValueError('Not an NTLM Type 2 message')

    # Extract Target Name details
    target_name_len = struct.unpack('<H', ntlm_bytes[12:14])[0]
    target_name_offset = struct.unpack('<I', ntlm_bytes[16:20])[0]
    target_name = ntlm_bytes[target_name_offset:target_name_offset+target_name_len].decode('utf-16le').strip('\x00')

    # Extract NetBIOS computer name and parse target information
    target_info_len = struct.unpack('<H', ntlm_bytes[40:42])[0]
    target_info_offset = struct.unpack('<I', ntlm_bytes[44:48])[0]
    target_info = ntlm_bytes[target_info_offset:target_info_offset + target_info_len]

    # Parse target information fields (MsvAvNbComputerName, MsvAvNbDomainName, etc.)
    def parse_av_pairs(data):
        av_pairs = {}
        index = 0
        while index < len(data):
            av_id = struct.unpack('<H', data[index:index+2])[0]
            av_len = struct.unpack('<H', data[index+2:index+4])[0]
            av_value = data[index+4:index+4+av_len].decode('utf-16le').strip('\x00')
            av_pairs[av_id] = av_value
            index += 4 + av_len
            if av_id == 0:  # MsvAvEOL (end of list)
                break
        return av_pairs

    av_pairs = parse_av_pairs(target_info)

    # Extract version information
    version_offset = 48
    version = ntlm_bytes[version_offset:version_offset + 8]
    major_version = version[0]
    minor_version = version[1]
    build_number = struct.unpack('<H', version[2:4])[0]
    os_name = version_mapping.get((major_version, minor_version), f"Windows {major_version}.{minor_version}")
    version_str = f"{os_name} Build {build_number}"

    # Extract timestamp from the target information
    timestamp_offset = target_info.find(b'\x07\x00')
    if timestamp_offset != -1:
        timestamp_value = struct.unpack('<Q', target_info[timestamp_offset+4:timestamp_offset+12])[0]
        timestamp_dt = datetime(1601, 1, 1) + timedelta(microseconds=timestamp_value // 10)
    else:
        timestamp_dt = None

    # Construct the decoded information
    decoded_info = {
        "Target": target_name,
        "MsvAvNbComputerName": av_pairs.get(1, "<Not found>"),
        "MsvAvDnsDomainName": av_pairs.get(2, "<Not found>"),
        "Version": version_str,
        "MsvAvNbDomainName": av_pairs.get(3, "<Not found>"),
        "MsvAvDnsComputerName": av_pairs.get(4, "<Not found>"),
        "MsvAvDnsTreeName": av_pairs.get(5, "<Not found>"),
        "MsvAvTimestamp": timestamp_dt.strftime('%Y-%m-%d %H:%M:%S') if timestamp_dt else "<Not found>"
    }

    return decoded_info

# Function to generate the NTLM report
def generate_report(domain, endpoint, ntlm_response, request_headers, decoded_ntlm_info):
    decoded_info_str = "\n".join([f"{key}: {value}" for key, value in decoded_ntlm_info.items()])
    report_content = f"""
# Affected Endpoint:
Endpoint with the NTLM: {endpoint}

## Summary
The NTLM authentication process at this endpoint is leaking sensitive information via NTLMSSP (NT LAN Manager Security Support Provider) challenge messages, which are returned in the response headers during the NTLM handshake. Specifically, the challenge message discloses the following details:

## Steps To Reproduce:
Head to the Endpoint > Turn on Burp Suite Intercept > and input admin admin and click go > Do Intercept Response to this request > go to SSP Decoder and find the Information Decoded

## Decoded SSP Data:
{decoded_info_str}

## HTTP Request:
GET {endpoint} HTTP/1.1
Host: {domain}
User-Agent: {request_headers['User-Agent']}
Accept: {request_headers['Accept']}
Authorization: {request_headers['Authorization']}

## NTLM Response:
{ntlm_response}

## Recommended Fix:
1. Disable NTLM Authentication:
   If NTLM is not required for your environment, consider disabling NTLM authentication entirely. In favor of NTLM, you can use more secure protocols like Kerberos or OAuth.
   
2. Limit Exposure of NTLM Challenge Headers:
   If NTLM authentication is still required, you can reduce information leakage by ensuring that the NTLM challenge is only sent to trusted users and clients.

3. Configure proper access controls: Ensure that only authenticated and authorized users can trigger the NTLM challenge.

4. Use IP restrictions or firewalls: Limit NTLM authentication to internal or trusted networks by applying IP-based restrictions.

5. Enforce Strong NTLM Policies:
   - NTLMv2 Only: Ensure that your environment is configured to enforce NTLMv2, which is more secure than NTLMv1. In some cases, NTLMv1 may still be in use and more vulnerable to attacks.

### How to enforce NTLMv2:
- On Windows, you can enforce the use of NTLMv2 by configuring the Local Security Policy or Group Policy.
- Go to Local Security Policy > Security Options.
- Set Network security: LAN Manager authentication level to Send NTLMv2 response only, refuse LM & NTLM.

## Summary:
- Information Disclosure: The NTLMSSP response exposes critical details about the internal infrastructure, including domain and machine names.
- NTLM Relay Attack: With the NTLMSSP details, an attacker can perform a relay attack, where the NTLM authentication from a legitimate user is intercepted and relayed to another service. This could allow unauthorized access to resources on the network, potentially leading to privilege escalation.
- Credential Harvesting: By capturing the NTLM hash, an attacker could attempt to crack it offline using tools like Hashcat.
- Increased Attack Surface: The disclosed information can help an attacker in reconnaissance.

## Additional Information
The vulnerability could be leveraged using tools such as Metasploit's ms17_010_eternalblue for further exploitation in the network if the hash cracking or relay attack reveals additional vulnerabilities.
"""

    # Save the report to a file
    report_filename = f"NTLMReport-{domain.replace('.', '-')}.md"
    with open(report_filename, 'w') as report_file:
        report_file.write(report_content)
    print(colored(f"Report generated: {report_filename}", "green"))

# Function to handle multiple domains from a file
def process_domains_from_file(file_path):
    try:
        with open(file_path, 'r') as f:
            domains = f.readlines()
        for domain in domains:
            domain = domain.strip()  # Clean domain string
            if domain:
                check_all_paths(domain)
    except FileNotFoundError:
        print(colored(f"File {file_path} not found.", "red"))
    except Exception as e:
        print(colored(f"Error reading file {file_path}: {e}", "yellow"))

# Check all paths for NTLM and stop on first match
def check_all_paths(domain):
    clean_domain = clean_domain_input(domain)
    for path in paths:
        if check_ntlm(clean_domain, path):
            break  # Stop if NTLM is found
    else:
        print(colored(f"[-] No NTLM Response found for {domain}", "red"))

# Validate domain input (to remove any 'https://' or path components)
def clean_domain_input(domain):
    parsed_url = urlparse(domain)
    if parsed_url.scheme:
        return parsed_url.netloc  # Extract the domain without scheme
    return domain

# Main function to handle command-line arguments
def main():
    parser = argparse.ArgumentParser(description="NTLM Info Disclosure Scanner")
    
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-d", "--domain", help="Specify a single domain (e.g., domain.com)")
    group.add_argument("-l", "--list", help="Specify a file containing domains (one per line)")
    
    args = parser.parse_args()

    if args.domain:
        check_all_paths(args.domain)
    elif args.list:
        process_domains_from_file(args.list)

if __name__ == "__main__":
    main()
