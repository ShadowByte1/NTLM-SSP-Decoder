# NTLM-SSP-Decoder
This Python script decodes NTLM Security Support Provider (SSP) messages, specifically NTLM Type 2 messages, that are typically used during the authentication process in Windows environments. The script takes an NTLM SSP message encoded in Base64 and extracts key information such as the target computer name, domain, and version of Windows.

This script requires Python 3 to run. If you don't have Python installed, download and install it from Python's official website.

Clone the repository or download the script:

git clone https://github.com/ShadowByte1/NTLM-SSP-Decoder

cd NTLM-SSP-Decoder

Ensure that python3 is installed and accessible from the command line:

python3 --version

Usage
To use the script, simply run the following command:

python3 SSPDecoder.py -u "<Base64-encoded NTLM SSP message>"

Copy code
python3 SSPDecoder.py -u "NTLM encoded SSP Message Here"

The script will output key details decoded from the NTLM SSP message:

```
Raw NTLM bytes (hex): <raw bytes in hex for debugging purposes>

Target: Example

MsvAvNbComputerName: Example

MsvAvDnsDomainName: Example

Version: Windows Server 2012 R2 / Windows 8.1

MsvAvNbDomainName: Example

MsvAvDnsComputerName: Example

MsvAvDnsTreeName: Example

MsvAvTimestamp: 2024-10-09 01:07:14
```

How It Works
NTLM SSP and Type 2 Messages
NTLM messages are part of the challenge/response authentication protocol used by Windows systems. In a typical NTLM authentication sequence, a Type 2 message is issued by the server in response to the client’s Type 1 message. This Type 2 message contains various fields, such as:

Target name
NetBIOS computer name
DNS domain name
Windows version information
Timestamp
These fields are encoded in Base64 and sent to the client for further processing in the authentication handshake.

Decoding Process
The script performs the following key steps:

Base64 Decoding: The input message is first decoded from Base64 into raw bytes.
Message Validation: The first part of the message is checked for the NTLM signature to ensure it is a valid NTLM message.
Field Extraction:
Target Name: Extracted from the message using offsets and length.
NetBIOS and DNS Information: The computer name and domain are extracted by parsing Attribute Value (AV) pairs.
Windows Version: The major, minor version, and build number of the Windows system are extracted.
Timestamp: The NTLM timestamp (in FileTime format) is converted into a human-readable datetime format.
Output: The extracted information is printed in a readable format for analysis.
Decoded Information
The script will output the following information based on the NTLM Type 2 message:

Target: The NetBIOS name of the target server.
MsvAvNbComputerName: The NetBIOS name of the server.
MsvAvDnsDomainName: The DNS domain name of the target server.
Version: The Windows operating system version and build number (e.g., Windows Server 2012 R2 / Windows 8.1).
MsvAvNbDomainName: The NetBIOS domain name.
MsvAvDnsComputerName: The fully qualified DNS name of the server.
MsvAvDnsTreeName: The DNS tree name for the server's domain.
MsvAvTimestamp: The NTLM timestamp converted into a human-readable format.
Troubleshooting
Invalid NTLM Message
If the script outputs an error like Not an NTLM message, make sure the input is a valid Base64-encoded NTLM Type 2 message.

Incorrect Output
If some fields show as "<Not found>", this may be due to missing fields in the NTLM message or the server's response not containing the expected attributes.

Hex Dump
The script will print a hex dump of the raw NTLM message bytes for debugging purposes. This can help in understanding how the message is structured and where things might be going wrong.


## NTLM Report Generator / Scanner

NTLM Auto Scanner, Decoder, and Report Generator
This tool automates the detection of NTLM authentication responses, decodes the NTLM message to extract critical information, and generates a detailed report for each affected domain. The process is fully automated, and reports are saved in markdown format.

Features:

Auto Scanner: Automatically checks predefined NTLM endpoints (/owa/, /Autodiscover/, etc.) on specified domains to detect NTLM authentication challenges.

NTLM Decoder: Decodes the NTLM SSP (NT LAN Manager Security Support Provider) message, extracting key details such as target information, version, domain, and timestamps.

Report Generator: Generates a comprehensive report for each domain, including decoded NTLM information and remediation recommendations.

How It Works:

NTLM Response Detection: The tool sends requests to common NTLM authentication endpoints. If an NTLM authentication challenge is found in the server's response, the tool captures the NTLM message.

NTLM Message Decoding: The captured NTLM message is base64 decoded and parsed. Important details such as computer name, domain name, and the Windows version are extracted.

Report Generation: For each domain where an NTLM response is detected, a markdown report is generated with the decoded information and recommendations for fixing the issue.

Usage:
Scan a Single Domain:
To scan a single domain and generate a report if an NTLM response is found:

python3 ntlmreport.py -d domain.com
Scan Multiple Domains from a File:
You can also pass a file containing multiple domains (one per line). The tool will scan each domain and generate a report if an NTLM response is detected:


python3 ntlmreport.py -l domains.txt
Report Format:
For each detected NTLM response, the tool generates a report in markdown format, saved as NTLMReport-domain.com.md. The report includes the following sections:

Affected Endpoint: The URL of the endpoint that leaked NTLM information.

Summary: An explanation of how NTLM is leaking sensitive information and what is exposed.

Steps to Reproduce: Instructions on how to replicate the finding using tools like Burp Suite.

Decoded SSP Data: A section with detailed information extracted from the NTLM challenge, such as:

Target computer name

Domain name

Windows version

Timestamp (if available)

HTTP Request: The exact HTTP request that triggered the NTLM response.

NTLM Response: The NTLM response header captured from the server.

Recommended Fixes: Suggestions on how to mitigate the issue, including disabling NTLM, using Kerberos, or limiting exposure.

