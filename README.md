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
Example
bash
Copy code
python3 SSPDecoder.py -u "NTLM encoded SSP Message Here"

The script will output key details decoded from the NTLM SSP message:

Raw NTLM bytes (hex): <raw bytes in hex for debugging purposes>
Target: Example
MsvAvNbComputerName: Example
MsvAvDnsDomainName: Example
Version: Windows Server 2012 R2 / Windows 8.1
MsvAvNbDomainName: Example
MsvAvDnsComputerName: Example
MsvAvDnsTreeName: Example
MsvAvTimestamp: 2024-10-09 01:07:14

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

