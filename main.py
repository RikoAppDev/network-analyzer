from scapy.all import *
import binascii
import ruamel.yaml
import os

import constants


# Finds file between project structure
def find_file(file_name):
    directory = os.path.dirname(os.path.abspath(__file__ or ''))

    file_paths = []
    for root, dirs, files in os.walk(directory):
        if file_name in files:
            file_paths.append(os.path.join(root, file_name))
    return file_paths


# Sets file name
def set_file(file):
    file_paths = find_file(file)
    if len(file_paths) > 1:
        print("WARNING!\nFile found at the following locations within your project structure:")
        for path in file_paths:
            print(path)
        print("Make sure there are no file name duplicates!")
        exit()
    elif len(file_paths) == 1:
        constants.PCAP_FILE = file_paths[0]
        return True

    return False


# Returns file name from whole file path
def get_pcap_file():
    return constants.PCAP_FILE.split("\\")[len(constants.PCAP_FILE.split("\\")) - 1]


# Returns file name with supported file type if missing
def append_file_type(file):
    if file.endswith(".pcap"):
        return file
    else:
        return file + ".pcap"


# Outputs data into yaml file
def stream_data_into_yaml(yaml_file_path, data_to_stream):
    with open(yaml_file_path, 'w') as file:
        try:
            yaml.dump(data_to_stream, file)
            print(f'\nData has been successfully streamed to {yaml_file_path}')
        except Exception as exc:
            print(f'\n!!!Error while streaming data to {yaml_file_path}, error: {exc}!!!')


# Returns formatted hex dump from byte array
def formatted_hexdump(hex_dump):
    hex_dump_str = " ".join(format(byte, "02X") for byte in hex_dump)
    hex_dump_str = [hex_dump_str[i:i + 47] for i in range(0, len(hex_dump_str), 48)]
    hex_dump_str = "\n".join(hex_dump_str) + "\n"

    return hex_dump_str


# Returns byte array from formatted hex dump
def reverse_formatted_hexdump(hex_dump_str):
    hex_dump_str = hex_dump_str.replace('\n', '').replace(' ', '')
    hex_pairs = [hex_dump_str[i:i + 2] for i in range(0, len(hex_dump_str), 2)]
    bytes_data = hex_bytes(''.join(hex_pairs))

    return bytes_data


# Appends information about mac addresses to its packet
def append_mac_addresses():
    packet_info.setdefault("src_mac", source_mac)
    packet_info.setdefault("dst_mac", destination_mac)


# Appends information about IPv4 addresses to its packet
def append_ip_addresses(s_ip, d_ip):
    packet_info.setdefault("src_ip", s_ip)
    packet_info.setdefault("dst_ip", d_ip)


# Returns offset value form IPv4 header
def get_ip_header_offset():
    ihl = (packet_data[14] & 0x0F)
    header_length_bytes = ihl * 4
    return header_length_bytes - 20


# Checks if packet is from the same communication
def is_packet_from_same_comm(c, looking_packet):
    if (
            looking_packet.get("src_ip") == c.get("dst_ip") and
            looking_packet.get("dst_ip") == c.get("src_ip") and
            looking_packet.get("src_port") == c.get("dst_port") and
            looking_packet.get("dst_port") == c.get("src_port")
    ) or (
            looking_packet.get("src_ip") == c.get("src_ip") and
            looking_packet.get("dst_ip") == c.get("dst_ip") and
            looking_packet.get("src_port") == c.get("src_port") and
            looking_packet.get("dst_port") == c.get("dst_port")
    ):
        return True
    return False


# Control possible end of comm
def has_fin_pattern(flag_list):
    if flag_list[0] == ["FIN", "ACK"]:
        if flag_list[1] == ["ACK"]:
            if flag_list[len(flag_list) - 2] == ["FIN", "ACK"]:
                if flag_list[len(flag_list) - 1] == ["ACK"]:
                    return True

    return False


# Returns needed active flags
def get_active_flags(p_data):
    flags = bin(p_data[47 + get_ip_header_offset()])
    flags = flags[2:].zfill(5)

    active_flags = []
    if flags[4] == "1":
        active_flags.append("FIN")
    if flags[3] == "1":
        active_flags.append("SYN")
    if flags[2] == "1":
        active_flags.append("RST")
    if flags[0] == "1":
        active_flags.append("ACK")

    return active_flags


yaml = ruamel.yaml.YAML()

with open(constants.OPTIONS_INFO_FILE, 'r') as yaml_file:
    options_info_data = yaml.load(yaml_file)

pcap_file = append_file_type(input('Input "pcap" file >> '))
while not set_file(pcap_file):
    print(f"!!!Error!!!\nFile {pcap_file} not found within your project structure!")
    pcap_file = append_file_type(input('Input "pcap" file >> '))

packets = rdpcap(constants.PCAP_FILE)
counter = 0
packets_to_yaml = []

ip_nodes_to_yaml = []
ip_nodes = {}

# Loops through all packets and make appropriate analysis
for packet in packets:
    packet_data = binascii.unhexlify(bytes_hex(packet))
    counter += 1

    # Ethernet header
    ethernet_header = packet_data[:14]

    source_mac = ":".join(format(byte, "02X") for byte in ethernet_header[:6])
    destination_mac = ":".join(format(byte, "02X") for byte in ethernet_header[6:12])
    ether_type = "".join(format(byte, "02X") for byte in ethernet_header[12:14])

    pcap_frame_length = len(packet)

    medium_frame_length = max(64, pcap_frame_length + 4)

    packet_info: dict = {
        "frame_number": counter,
        "len_frame_pcap": pcap_frame_length,
        "len_frame_medium": medium_frame_length,
    }

    # Ethernet type
    frame_type = "Ethernet II"
    if int(ether_type, 16) > 1500:
        frame_type = "Ethernet II"
        packet_info.setdefault("frame_type", frame_type)
        append_mac_addresses()

        # ARP
        if int(ether_type, 16) == 2054:
            arp_header_data = packet_data[14:42]

            operation_code = "".join(f"{byte:02X}" for byte in arp_header_data[6:8])
            source_protocol_addr = arp_header_data[14:18]
            target_protocol_addr = arp_header_data[24:28]

            packet_info.setdefault("ether_type", options_info_data["ether_types"][int(ether_type, 16)])
            packet_info.setdefault("arp_opcode", options_info_data["arp_opcode"][int(operation_code, 16)])
            source_protocol_addr_str = '.'.join(map(str, source_protocol_addr))
            target_protocol_addr_str = '.'.join(map(str, target_protocol_addr))
            append_ip_addresses(source_protocol_addr_str, target_protocol_addr_str)

        # IPv4 version
        elif int(ether_type, 16) == 2048:
            packet_info.setdefault("ether_type", options_info_data["ether_types"][int(ether_type, 16)])

            offset = get_ip_header_offset()

            ip_header = packet_data[14:34 + offset]

            protocol = bytes_hex(ip_header[9:10])

            source_ip_address = ip_header[12:16]
            destination_ip_address = ip_header[16:20]

            source_ip_str = '.'.join(map(str, source_ip_address))
            destination_ip_str = '.'.join(map(str, destination_ip_address))
            append_ip_addresses(source_ip_str, destination_ip_str)

            val = ip_nodes.get(source_ip_str)

            if val is None:
                ip_nodes.setdefault(source_ip_str, 1)
            else:
                val += 1
                ip_nodes.update({source_ip_str: val})

            packet_info.setdefault("protocol", options_info_data["transport_protocol"][int(protocol, 16)])

            # TCP UDP ports
            if int(protocol, 16) == 6 or int(protocol, 16) == 17:
                src_port = "".join(f"{byte:02X}" for byte in packet_data[34 + offset:36 + offset])
                dst_port = "".join(f"{byte:02X}" for byte in packet_data[36 + offset:38 + offset])

                packet_info.setdefault("src_port", int(src_port, 16))
                packet_info.setdefault("dst_port", int(dst_port, 16))
                try:
                    packet_info.setdefault("app_protocol", options_info_data["wellknown_ports"][int(src_port, 16)])
                except KeyError as e:
                    try:
                        packet_info.setdefault("app_protocol", options_info_data["wellknown_ports"][int(dst_port, 16)])
                    except KeyError as e:
                        pass
        else:
            try:
                packet_info.setdefault("ether_type", options_info_data["ether_types"][int(ether_type, 16)])
            except KeyError as e:
                print(f"frame_number: {packet_info.get('frame_number')}")
                print(f"ether_type {e}: UNKNOWN")

    elif int(ether_type, 16) <= 1500:
        # ISL header remove
        if (packet_data[:5] == binascii.unhexlify(bytes_hex(b"\x01\x00\x0c\x00\x00"))
                or packet_data[:5] == binascii.unhexlify(bytes_hex(b"\x03\x00\x0c\x00\x00"))):
            isl_header_size = 26
            packet_data = packet_data[isl_header_size:]

        # LLC Header
        dsap = bytes_hex(packet_data[14:15])

        if int(dsap, 16) == 170:
            frame_type = "IEEE 802.3 LLC & SNAP"
            pid = "".join(f"{byte:02X}" for byte in packet_data[20:22])

            packet_info.setdefault("frame_type", frame_type)
            append_mac_addresses()
            packet_info.setdefault("pid", options_info_data["pid"][int(pid, 16)])
        elif int(dsap, 16) == 255:
            frame_type = "IEEE 802.3 RAW"

            packet_info.setdefault("frame_type", frame_type)
            append_mac_addresses()
        else:
            frame_type = "IEEE 802.3 LLC"

            packet_info.setdefault("frame_type", frame_type)
            append_mac_addresses()
            packet_info.setdefault("sap", options_info_data["sap"][int(dsap, 16)])

    packet_info.setdefault("hexa_frame", ruamel.yaml.scalarstring.LiteralScalarString(formatted_hexdump(packet_data)))
    packets_to_yaml.append(packet_info)

# Filter and stream to yaml file
with open(constants.PROTOCOL_FILTERS_FILE, 'r') as yaml_file:
    protocol_filters = yaml.load(yaml_file)

print(
    "Supported filters: HTTP | HTTPS | TELNET | SSH | FTP-CONTROL | FTP-DATA | TFTP | ICMP | ARP | X (additional implementation ftp-data)")
filter_protocol = input("Apply some protocol filter (ESC for no filter) >> ").upper()

while filter_protocol not in protocol_filters["protocol_filters"] and filter_protocol != "ESC":
    print(f"Error: protocol {filter_protocol} is not supported as filter!")
    print(
        "Supported filters: HTTP | HTTPS | TELNET | SSH | FTP-CONTROL | FTP-DATA | TFTP | ICMP | ARP | X (additional implementation ftp-data)")
    filter_protocol = input("Apply some protocol filter (ESC for no filter) >> ").upper()

complete_communications = []
partial_communications = []
complete_communications_to_yaml = []
partial_communications_to_yaml = []

if filter_protocol == "ESC":
    # Find all communications between different nodes
    for ip in ip_nodes:
        node = {
            "node": ip,
            "number_of_sent_packets": ip_nodes[ip],
        }
        ip_nodes.values()
        ip_nodes_to_yaml.append(node)

    max_value_ip_nodes = [ip for ip, value in ip_nodes.items() if value == max(ip_nodes.values())]

    data = {
        'name': 'PKS2023/24',
        'pcap_name': get_pcap_file(),
        'packets': packets_to_yaml,
        'ipv4_senders': ip_nodes_to_yaml,
        'max_send_packets_by': max_value_ip_nodes,
    }

    stream_data_into_yaml("packets-all.yaml", data)
elif filter_protocol == "ARP":
    for packet in packets_to_yaml:
        if packet.get("ether_type") == "ARP":
            if packet.get("arp_opcode") == "REQUEST":
                partial_communications.append(packet)
            elif packet.get("arp_opcode") == "REPLY":
                found_request = False
                for partial in partial_communications:
                    if partial.get("arp_opcode") == "REQUEST" and (
                            packet.get("src_ip") == partial.get("dst_ip") and
                            packet.get("dst_ip") == partial.get("src_ip")
                    ):
                        complete_communications.append(partial)
                        complete_communications.append(packet)
                        partial_communications.remove(partial)
                        found_request = True

                if not found_request:
                    partial_communications.append(packet)

    # Format communications data into suitable output format
    if len(complete_communications) != 0:
        complete_comm_info: dict = {
            "number_comm": 1,
            "packets": complete_communications
        }
        complete_communications_to_yaml.append(complete_comm_info)

    arp_partial_request = []
    arp_partial_reply = []

    for partial in partial_communications:
        if partial.get("arp_opcode") == "REQUEST":
            arp_partial_request.append(partial)
        elif partial.get("arp_opcode") == "REPLY":
            arp_partial_reply.append(partial)

    number_comm = 1
    if len(arp_partial_request) != 0:
        partial_comm_info: dict = {
            "number_comm": number_comm,
            "packets": arp_partial_request
        }
        partial_communications_to_yaml.append(partial_comm_info)
        number_comm += 1

    if len(arp_partial_reply) != 0:
        partial_comm_info: dict = {
            "number_comm": number_comm,
            "packets": arp_partial_reply
        }
        partial_communications_to_yaml.append(partial_comm_info)

    data = {
        'name': 'PKS2023/24',
        'pcap_name': get_pcap_file(),
        'filter_name': 'ARP',
    }
    if len(complete_communications_to_yaml) != 0:
        data.setdefault("complete_comms", complete_communications_to_yaml)
    if len(partial_communications_to_yaml) != 0:
        data.setdefault("partial_comms", partial_communications_to_yaml)

    stream_data_into_yaml("packets-arp.yaml", data)
elif filter_protocol == "ICMP":
    for packet in packets_to_yaml:
        if packet.get("protocol") == "ICMP":
            source_ip = packet.get("src_ip")
            destination_ip = packet.get("dst_ip")

            packet_data = reverse_formatted_hexdump(packet.get("hexa_frame"))

            offset = get_ip_header_offset()

            icmp_type = f"{packet_data[34 + offset]:02X}"

            packet.popitem()
            packet.setdefault("icmp_type", options_info_data["icmp_type"][int(icmp_type, 16)])

            # Correct icmp data for ttl-exceeded
            if int(icmp_type, 16) == 11:
                icmp_id_str = "".join(f"{byte:02X}" for byte in packet_data[66 + offset:68 + offset])
                icmp_seq_str = "".join(f"{byte:02X}" for byte in packet_data[68 + offset:70 + offset])

            elif int(icmp_type, 16) == 0 or int(icmp_type, 16) == 8:
                icmp_id_str = "".join(f"{byte:02X}" for byte in packet_data[38 + offset:40 + offset])
                icmp_seq_str = "".join(f"{byte:02X}" for byte in packet_data[40 + offset:42 + offset])

            icmp_id = int(icmp_id_str, 16)
            icmp_seq = int(icmp_seq_str, 16)
            packet.setdefault("icmp_id", icmp_id)
            packet.setdefault("icmp_seq", icmp_seq)
            packet.setdefault(
                "hexa_frame",
                ruamel.yaml.scalarstring.LiteralScalarString(formatted_hexdump(packet_data))
            )

            # REQUEST
            if int(icmp_type, 16) == 8:
                comm_info: dict = {
                    "src_comm": source_ip,
                    "dst_comm": destination_ip,
                    "packets": [packet],
                    "icmp_id": icmp_id,
                }
                partial_communications.append(comm_info)
            # REPLY or TTL exceeded
            elif int(icmp_type, 16) == 0 or int(icmp_type, 16) == 11:
                found_in_partial_comm = False

                if int(icmp_type, 16) == 11:
                    ip_header = packet_data[42 + offset:62 + offset]
                    packet_src = ip_header[12:16]
                    packet_dst = ip_header[16:20]
                    packet_src_str = '.'.join(map(str, packet_src))
                    packet_dst_str = '.'.join(map(str, packet_dst))

                for partial_comm in partial_communications:
                    if int(icmp_type, 16) == 0 and (
                            packet.get("dst_ip") == partial_comm.get("src_comm") and
                            packet.get("src_ip") == partial_comm.get("dst_comm") and
                            packet.get("icmp_id") == partial_comm.get("icmp_id")
                    ) or int(icmp_type, 16) == 11 and (
                            packet_src_str == partial_comm.get("src_comm") and
                            packet_dst_str == partial_comm.get("dst_comm") and
                            packet.get("icmp_id") == partial_comm.get("icmp_id")
                    ):
                        found_in_partial_comm = True
                        partial_comm_packets: list = partial_comm.get("packets")

                        for p in partial_comm_packets:
                            # Check if communications already exist
                            found_in_complete_comm = False
                            for complete_comm in complete_communications:
                                if (
                                        complete_comm.get("src_comm") == partial_comm.get("src_comm") and
                                        complete_comm.get("dst_comm") == partial_comm.get("dst_comm") and
                                        complete_comm.get("icmp_id") == partial_comm.get("icmp_id")
                                ):
                                    complete_comm_packets: list = complete_comm.get("packets")
                                    complete_comm_packets.append(p)
                                    complete_comm_packets.append(packet)
                                    found_in_complete_comm = True

                            if not found_in_complete_comm:
                                comm_info: dict = {
                                    "src_comm": partial_comm.get("src_comm"),
                                    "dst_comm": partial_comm.get("dst_comm"),
                                    "packets": [p, packet],
                                    "icmp_id": icmp_id,
                                }
                                complete_communications.append(comm_info)
                            partial_communications.remove(partial_comm)
                if not found_in_partial_comm:
                    comm_info: dict = {
                        "src_comm": source_ip,
                        "dst_comm": destination_ip,
                        "packets": [packet],
                        "icmp_id": icmp_id,
                    }
                    partial_communications.append(comm_info)
            # OTHERS
            else:
                comm_info: dict = {
                    "src_comm": source_ip,
                    "dst_comm": destination_ip,
                    "packets": [packet],
                    "icmp_id": icmp_id,
                }
                partial_communications.append(comm_info)

    # Format communications data into suitable output format
    counter = 1
    for comm in complete_communications:
        complete_comm_to_yaml = {
            "number_comm": counter,
            "src_comm": comm.get("src_comm"),
            "dst_comm": comm.get("dst_comm"),
            "packets": comm.get("packets"),
        }
        complete_communications_to_yaml.append(complete_comm_to_yaml)
        counter += 1

    counter = 1
    for comm in partial_communications:
        comm_packets = comm.get("packets")
        for p in comm_packets:
            p.pop("icmp_id")
            p.pop("icmp_seq")

        partial_comm_to_yaml = {
            "number_comm": counter,
            "packets": comm.get("packets"),
        }
        partial_communications_to_yaml.append(partial_comm_to_yaml)
        counter += 1

    data = {
        'name': 'PKS2023/24',
        'pcap_name': get_pcap_file(),
        'filter_name': 'ICMP',
    }
    if len(complete_communications_to_yaml) != 0:
        data.setdefault("complete_comms", complete_communications_to_yaml)
    if len(partial_communications_to_yaml) != 0:
        data.setdefault("partial_comms", partial_communications_to_yaml)

    stream_data_into_yaml("packets-icmp.yaml", data)
elif filter_protocol == "TFTP":
    counter = 0
    end_of_comm = False
    for packet in packets_to_yaml:
        if packet.get("protocol") == "UDP":
            packet_data = reverse_formatted_hexdump(packet.get("hexa_frame"))
            if packet.get("app_protocol") == "TFTP":
                counter = 1
                end_of_comm = False
                offset = get_ip_header_offset()

                tftp_type = "".join(f"{byte:02X}" for byte in packet_data[42 + offset:44 + offset])

                communication = {
                    "tftp_type": options_info_data["tftp_type"][int(tftp_type, 16)],
                    "src_ip": packet.get("src_ip"),
                    "dst_ip": packet.get("dst_ip"),
                    "src_port": packet.get("src_port"),
                    "dst_port": packet.get("dst_port"),
                    "packets": [packet],
                    "data_size": -1,
                }
                partial_communications.append(communication)
            else:
                # Find ongoing communication
                for comm in partial_communications:
                    if comm.get("dst_port") == 69 and (
                            packet.get("src_ip") == comm.get("dst_ip") and
                            packet.get("dst_ip") == comm.get("src_ip") and
                            packet.get("dst_port") == comm.get("src_port")
                    ):
                        comm.update({"dst_port": packet.get("src_port")})

                    if comm.get("data_size") == -1:
                        if comm.get("tftp_type") == options_info_data["tftp_type"][int("01", 16)] and counter == 1:
                            data_size = "".join(f"{byte:02X}" for byte in packet_data[38 + offset:40 + offset])
                            comm.update({"data_size": int(data_size, 16)})
                        elif comm.get("tftp_type") == options_info_data["tftp_type"][int("02", 16)] and counter == 2:
                            data_size = "".join(f"{byte:02X}" for byte in packet_data[38 + offset:40 + offset])
                            comm.update({"data_size": int(data_size, 16)})

                    if is_packet_from_same_comm(comm, packet):
                        packet_data = reverse_formatted_hexdump(packet.get("hexa_frame"))

                        comm_packets = comm.get("packets")
                        comm_packets.append(packet)
                        comm.update({"packets": comm_packets})

                        if end_of_comm:
                            complete_communications.append(comm)
                            partial_communications.remove(comm)

                        packet_data_size = "".join(f"{byte:02X}" for byte in packet_data[38 + offset:40 + offset])
                        if comm.get("tftp_type") == options_info_data["tftp_type"][int("01", 16)]:
                            if (
                                    packet.get("src_ip") == comm.get("dst_ip") and
                                    packet.get("dst_ip") == comm.get("src_ip") and
                                    packet.get("src_port") == comm.get("dst_port") and
                                    packet.get("dst_port") == comm.get("src_port")
                            ) and (int(packet_data_size, 16) < comm.get("data_size") or int(packet_data_size,
                                                                                            16) < 512):
                                end_of_comm = True
                        elif comm.get("tftp_type") == options_info_data["tftp_type"][int("02", 16)]:
                            if (
                                    packet.get("src_ip") == comm.get("src_ip") and
                                    packet.get("dst_ip") == comm.get("dst_ip") and
                                    packet.get("src_port") == comm.get("src_port") and
                                    packet.get("dst_port") == comm.get("dst_port")
                            ) and (int(packet_data_size, 16) < comm.get("data_size") or int(packet_data_size,
                                                                                            16) < 512):
                                end_of_comm = True
                        counter += 1

    # Format communications data into suitable output format
    counter = 1
    for comm in complete_communications:
        complete_comm_to_yaml = {
            "number_comm": counter,
            "src_comm": comm.get("src_ip"),
            "dst_comm": comm.get("dst_ip"),
            "packets": comm.get("packets"),
        }
        complete_communications_to_yaml.append(complete_comm_to_yaml)
        counter += 1

    counter = 1
    for comm in partial_communications:
        partial_comm_to_yaml = {
            "number_comm": counter,
            "packets": comm.get("packets"),
        }
        partial_communications_to_yaml.append(partial_comm_to_yaml)
        counter += 1

    data = {
        'name': 'PKS2023/24',
        'pcap_name': get_pcap_file(),
        'filter_name': "TFTP",
    }
    if len(complete_communications_to_yaml) != 0:
        data.setdefault("complete_comms", complete_communications_to_yaml)
    if len(partial_communications_to_yaml) != 0:
        data.setdefault("partial_comms", partial_communications_to_yaml)

    stream_data_into_yaml(f"packets-tftp.yaml", data)
elif filter_protocol in protocol_filters["tcp_filters"]:
    for packet in packets_to_yaml:
        if packet.get("protocol") == "TCP" and packet.get("app_protocol") == filter_protocol:
            packet_data = reverse_formatted_hexdump(packet.get("hexa_frame"))

            found_in_comm = False
            for comm in partial_communications:
                # Find ongoing communication
                if is_packet_from_same_comm(comm, packet):
                    if not comm.get("est"):
                        est_flags = comm.get("est_flags")
                        est_flags.append(get_active_flags(packet_data))
                        comm.update({"est_flags": est_flags})

                        if (
                                est_flags == [['SYN'], ['SYN', 'ACK'], ['ACK']] or
                                est_flags == [['SYN'], ['SYN'], ['ACK'], ['ACK']]
                        ):
                            comm.update({"est": True})

                    comm_packets: list = comm.get("packets")
                    comm_packets.append(packet)

                    # Check if some device want to finish communication
                    if "FIN" in get_active_flags(packet_data):
                        comm.update({"wanna_terminate": True})

                    if comm.get("wanna_terminate"):
                        trm_flags: list = comm.get("trm_flags")
                        trm_flags.append(get_active_flags(packet_data))
                        comm.update({"trm_flags": trm_flags})
                        comm.update({"trm": True})

                        if comm.get("est") and (
                                (len(trm_flags) >= 4 and has_fin_pattern(trm_flags)) or
                                trm_flags == [["FIN", "ACK"], ["FIN", "ACK"], ["ACK"]]
                        ):
                            complete_communications.append(comm)
                            partial_communications.remove(comm)

                    if "RST" in get_active_flags(packet_data) and comm.get("est"):
                        trm_flags: list = comm.get("trm_flags")
                        trm_flags.append(get_active_flags(packet_data))
                        comm.update({"trm_flags": trm_flags})
                        comm.update({"trm": True})
                        complete_communications.append(comm)
                        partial_communications.remove(comm)

                    found_in_comm = True

            # Create communication if is new
            if not found_in_comm:
                communication: dict = {
                    "est": False,
                    "trm": False,
                    "wanna_terminate": False,
                    "est_flags": [get_active_flags(packet_data)],
                    "trm_flags": [],
                    "src_ip": packet.get("src_ip"),
                    "dst_ip": packet.get("dst_ip"),
                    "src_port": packet.get("src_port"),
                    "dst_port": packet.get("dst_port"),
                    "packets": [packet],
                }
                partial_communications.append(communication)

    # Format communications data into suitable output format
    counter = 1
    for comm in complete_communications:
        complete_comm_to_yaml = {
            "number_comm": counter,
            "src_comm": comm.get("src_ip"),
            "dst_comm": comm.get("dst_ip"),
            "packets": comm.get("packets"),
        }
        complete_communications_to_yaml.append(complete_comm_to_yaml)
        counter += 1

    for comm in partial_communications:
        if comm.get("est") or comm.get("trm"):
            partial_comm_to_yaml = {
                "number_comm": 1,
                "packets": comm.get("packets"),
            }
            partial_communications_to_yaml.append(partial_comm_to_yaml)
            break

    data = {
        'name': 'PKS2023/24',
        'pcap_name': get_pcap_file(),
        'filter_name': filter_protocol,
    }
    if len(complete_communications_to_yaml) != 0:
        data.setdefault("complete_comms", complete_communications_to_yaml)
    if len(partial_communications_to_yaml) != 0:
        data.setdefault("partial_comms", partial_communications_to_yaml)

    stream_data_into_yaml(f"packets-{filter_protocol.lower()}.yaml", data)
elif filter_protocol == "X":
    ftp_data_packets = []

    for packet in packets_to_yaml:
        if packet.get("protocol") == "TCP" and packet.get("app_protocol") == "FTP-DATA":
            if packet.get("len_frame_medium") > 82:
                ftp_data_packets.append(packet)

    data = {
        'name': 'PKS2023/24',
        'pcap_name': get_pcap_file(),
        'packets': ftp_data_packets,
        'number_frames': len(ftp_data_packets)
    }

    stream_data_into_yaml("doimplementacia-packets-ftp-data.yaml", data)
