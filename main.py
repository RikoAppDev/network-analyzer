from scapy.all import *
import binascii
import ruamel.yaml

from constants import *


def get_pcap_file():
    return PCAP_FILE.split("/")[len(PCAP_FILE.split("/")) - 1]


def stream_data_into_yaml(yaml_file_path, data_to_stream):
    with open(yaml_file_path, 'w') as file:
        try:
            yaml.dump(data_to_stream, file)
            print(f'\nData has been successfully streamed to {yaml_file_path}')
        except Exception as e:
            print(f'\n!!!Error while streaming data to {yaml_file_path}, error: {e}!!!')


def formatted_hexdump(hex_dump):
    hex_dump_str = " ".join(format(byte, "02X") for byte in hex_dump)
    hex_dump_str = [hex_dump_str[i:i + 47] for i in range(0, len(hex_dump_str), 48)]
    hex_dump_str = "\n".join(hex_dump_str) + "\n"

    return hex_dump_str


def reverse_formatted_hexdump(hex_dump_str):
    hex_dump_str = hex_dump_str.replace('\n', '').replace(' ', '')
    hex_pairs = [hex_dump_str[i:i + 2] for i in range(0, len(hex_dump_str), 2)]
    bytes_data = hex_bytes(''.join(hex_pairs))

    return bytes_data


def append_mac_addresses():
    packet_info.setdefault("src_mac", source_mac)
    packet_info.setdefault("dst_mac", destination_mac)


def append_ip_addresses(source_ip, dest_ip):
    packet_info.setdefault("src_ip", source_ip)
    packet_info.setdefault("dst_ip", dest_ip)


def get_ip_header_offset():
    ihl = (packet_data[14] & 0x0F)
    header_length_bytes = ihl * 4
    return header_length_bytes - 20


yaml = ruamel.yaml.YAML()

with open(OPTIONS_INFO_FILE, 'r') as yaml_file:
    options_info_data = yaml.load(yaml_file)

packets = rdpcap(PCAP_FILE)
counter = 0
packets_to_yaml = []

ip_nodes_to_yaml = []
ip_nodes = {}

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

        # IP version
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
protocol_filters_file = "protocol_filters.yml"

with open(protocol_filters_file, 'r') as yaml_file:
    protocol_filters = yaml.load(yaml_file)

print("Apply some protocol filter (ESC for no filter) >> ", end="")
# filter_protocol = input().upper()
filter_protocol = "TFTP"

while filter_protocol not in protocol_filters["protocol_filters"] and filter_protocol != "ESC":
    print(f"Error: protocol {filter_protocol} is not supported as filter!")
    print("Supported filters: HTTP | HTTPS | TELNET | SSH | FTP-CONTROL | FTP-DATA | TFTP | ICMP | ARP")
    print("Apply some protocol filter (ESC for no filter) >> ", end="")
    filter_protocol = input().upper()

complete_communications = []
partial_communications = []
complete_communications_to_yaml = []
partial_communications_to_yaml = []

if filter_protocol == "ESC":
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
                    if partial.get("src_ip") == packet.get("dst_ip"):
                        complete_communications.append(partial)
                        complete_communications.append(packet)
                        partial_communications.remove(partial)
                        found_request = True

                if not found_request:
                    partial_communications.append(packet)

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
                counter = 0
                end_of_comm = False
                offset = get_ip_header_offset()

                tftp_type = "".join(f"{byte:02X}" for byte in packet_data[42 + offset:44 + offset])

                communication = {
                    "state": "PARTIAL",
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
                            comm.setdefault("data_size", int(data_size, 16))
                        elif comm.get("tftp_type") == options_info_data["tftp_type"][int("02", 16)] and counter == 2:
                            data_size = "".join(f"{byte:02X}" for byte in packet_data[38 + offset:40 + offset])
                            comm.setdefault("data_size", int(data_size, 16))

                    if (
                            packet.get("src_ip") == comm.get("dst_ip") and
                            packet.get("dst_ip") == comm.get("src_ip") and
                            packet.get("src_port") == comm.get("dst_port") and
                            packet.get("dst_port") == comm.get("src_port")
                    ) or (
                            packet.get("src_ip") == comm.get("src_ip") and
                            packet.get("dst_ip") == comm.get("dst_ip") and
                            packet.get("src_port") == comm.get("src_port") and
                            packet.get("dst_port") == comm.get("dst_port")
                    ):
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
                            ) and int(packet_data_size, 16) < comm.get("data_size"):
                                end_of_comm = True
                        elif comm.get("tftp_type") == options_info_data["tftp_type"][int("02", 16)]:
                            if (
                                    packet.get("src_ip") == comm.get("src_ip") and
                                    packet.get("dst_ip") == comm.get("dst_ip") and
                                    packet.get("src_port") == comm.get("src_port") and
                                    packet.get("dst_port") == comm.get("dst_port")
                            ) and int(packet_data_size, 16) < comm.get("data_size"):
                                end_of_comm = True
                        counter += 1

    counter = 1
    for comm in complete_communications:
        complete_comm_to_yaml = {
            "number_comm": counter,
            "data_size": comm.get("data_size"),
            "tftp_type": comm.get("tftp_type"),
            "src_comm": comm.get("src_ip"),
            "dst_comm": comm.get("dst_ip"),
            "src_port": comm.get("src_port"),
            "dst_port": comm.get("dst_port"),
            "packets": comm.get("packets"),
        }
        complete_communications_to_yaml.append(complete_comm_to_yaml)
        counter += 1

    counter = 1
    for comm in partial_communications:
        partial_comm_to_yaml = {
            "number_comm": counter,
            "data_size": comm.get("data_size"),
            "tftp_type": comm.get("tftp_type"),
            "src_comm": comm.get("src_ip"),
            "dst_comm": comm.get("dst_ip"),
            "src_port": comm.get("src_port"),
            "dst_port": comm.get("dst_port"),
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

    data = {
        'name': 'PKS2023/24',
        'pcap_name': get_pcap_file(),
        'filter_name': filter_protocol,
    }

    stream_data_into_yaml(f"packets-{filter_protocol.lower()}.yaml", data)
