import base64
import struct
import argparse
from datetime import datetime, timedelta

# A dictionary to map versions to OS names
version_mapping = {
    (6, 1): "Windows 7 / Windows Server 2008 R2",
    (6, 2): "Windows 8 / Windows Server 2012",
    (6, 3): "Windows 8.1 / Windows Server 2012 R2",
    (10, 0): "Windows 10 / Windows Server 2016/2019",
}

def decode_ntlm(ntlm_message):
    # Decode the base64-encoded NTLM message
    ntlm_bytes = base64.b64decode(ntlm_message)

    # Print raw byte data for debugging purposes
    print("Raw NTLM bytes (hex):", ntlm_bytes.hex())

    # NTLM Type 2 message structure
    signature = ntlm_bytes[:8].decode('ascii')
    if signature != 'NTLMSSP\x00':
        raise ValueError('Not an NTLM message')

    message_type = struct.unpack('<I', ntlm_bytes[8:12])[0]
    if message_type != 2:
        raise ValueError('Not an NTLM Type 2 message')

    # Extract Target Name details
    target_name_len = struct.unpack('<H', ntlm_bytes[12:14])[0]
    target_name_max_len = struct.unpack('<H', ntlm_bytes[14:16])[0]
    target_name_offset = struct.unpack('<I', ntlm_bytes[16:20])[0]

    # Extract target name string
    target_name = ntlm_bytes[target_name_offset:target_name_offset+target_name_len].decode('utf-16le').strip('\x00')

    # Extract NetBIOS computer name
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

    # Version information
    version_offset = 48
    version = ntlm_bytes[version_offset:version_offset + 8]
    major_version = version[0]
    minor_version = version[1]
    build_number = struct.unpack('<H', version[2:4])[0]
    
    # Use the mapping to get the human-readable OS name
    os_name = version_mapping.get((major_version, minor_version), f"Windows {major_version}.{minor_version}")
    version_str = f"{os_name} Build {build_number}"

    # Extract timestamp from the target information
    timestamp_offset = target_info.find(b'\x07\x00')  # Timestamp AV ID = 7
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

def main():
    # Setup argument parser to accept the NTLM message from user input
    parser = argparse.ArgumentParser(description="NTLM SSP Decoder")
    parser.add_argument("-u", "--ntlm", required=True, help="Base64-encoded NTLM SSP message")

    # Parse the arguments
    args = parser.parse_args()

    # Extract the NTLM message and strip any leading NTLM identifier
    ntlm_message = args.ntlm.split(" ")[-1]

    # Decode the NTLM message and display the results
    decoded_ntlm_info = decode_ntlm(ntlm_message)
    if decoded_ntlm_info:
        for key, value in decoded_ntlm_info.items():
            print(f"{key}: {value}")
    else:
        print("Failed to decode NTLM message.")

if __name__ == "__main__":
    main()
