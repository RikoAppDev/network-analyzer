# Network Analyzer 🕸️

This Network Analyzer tool captures and analyzes network packets using the Scapy library. It processes `.pcap` files and outputs relevant network information in a structured YAML format.

## Program Overview 📋

### Key Features
- **Packet Capture and Analysis**: Processes `.pcap` files to extract and analyze network packet data.
- **MAC and IP Address Extraction**: Identifies and logs source and destination MAC and IP addresses.
- **Protocol Identification**: Detects and records the protocol used in each packet.
- **Hex Dump Formatting**: Converts packet byte arrays into readable hex dump strings.
- **Active Flags Detection**: Identifies active TCP flags within packet data.

### Core Functions

1. **find_file(file_name)**: Searches for a file within the project structure.
2. **set_file(file)**: Sets the file path for the given file name.
3. **get_pcap_file()**: Returns the file name from the full file path.
4. **append_file_type(file)**: Appends the `.pcap` extension to a file name if it is missing.
5. **stream_data_into_yaml(yaml_file_path, data_to_stream)**: Streams data into a specified YAML file.
6. **formatted_hexdump(hex_dump)**: Formats a hex dump from a byte array into a readable string.
7. **reverse_formatted_hexdump(hex_dump_str)**: Converts a formatted hex dump string back into a byte array.
8. **append_mac_addresses()**: Appends MAC address information to the packet.
9. **append_ip_addresses(s_ip, d_ip)**: Appends IPv4 address information to the packet.
10. **get_ip_header_offset()**: Calculates the offset value from the IPv4 header.
11. **is_packet_from_same_comm(c, looking_packet)**: Checks if a packet is part of the same communication.
12. **has_fin_pattern(flag_list)**: Checks for the FIN pattern indicating the end of communication.
13. **get_active_flags(p_data)**: Returns active flags from the packet data.

### Output 📄

The tool generates a YAML file with detailed information about each packet, including:
- Frame number
- Length of frame in pcap and medium
- MAC addresses
- IP addresses
- Protocol information
- Hex dump of the packet

This structured data aids in network analysis and debugging by providing comprehensive insights into network traffic.

## Technical Documentation 📚

The technical documentation includes:

- Detailed architecture overview.
- Description of core functions and their usage.
- Workflow for packet processing.
- Explanation of file handling, YAML streaming, hex dump utilities, and MAC/IP address handling.

For detailed technical documentation, please check [Technical Documentation](Documentacia_PKS_Z1.pdf) in the repository.

