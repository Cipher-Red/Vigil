from scapy.all import *
import time
from colorama import Fore, Back, Style
from datetime import datetime
from collections import defaultdict


# Dictionary to track request counts
ip_request_count = {}

def save_to_pcap(packet):
    wrpcap("captured_traffic.pcap", packet, append=True)


def monitor(packet):
    # Gets The Time Of Capture Year - Month - Day - Hour - Minute - Second - Microseconds
    packet_time = datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S.%f')
    # Checks for the IP layer
    if IP in packet:
        save_to_pcap(packet)
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        dos_handler(packet)
        # Checks If there is a TCP packet
        if TCP in packet:

            # Checks If The packet is a HTTPS Packet Via Port Numbers
            if packet[TCP].dport == 443 or packet[TCP].sport == 443:
                print(Style.BRIGHT + Fore.BLACK + Back.WHITE + f"Connection type [HTTPS] & IP Address | Source IP - {src_ip} : Source Port - {packet.sport} | Destination IP - {dst_ip} : Destination Port - {packet.dport} | Time | {packet_time} |")
                # Checks For Payload
                if Raw in packet:
                    print(f"Payload Data: {packet[Raw].load} ")
                else:
                    print("No Payload Detected")

            # Checks For HTTP
            elif packet[TCP].dport == 80 or packet[TCP].sport == 80:
                print(Style.BRIGHT + Fore.BLACK + Back.WHITE + f"Connection type [HTTP] & IP Address | Source IP - {src_ip} : Source Port - {packet.sport} | Destination IP - {dst_ip} : Destination Port - {packet.dport} | Time | {packet_time} |")
                # Checks For Payload
                if Raw in packet:
                    print(f"Payload Data: {packet[Raw].load} ")
                else:
                    print("No Payload Detected")

            # Check For FTP Control channel
            elif packet[TCP].dport == 21 or packet[TCP].sport == 21:
                print(Style.BRIGHT + Fore.BLACK + Back.WHITE + f"Connection type [FTP] & IP Address | Source IP - {src_ip} : Source Port - {packet.sport} | Destination IP - {dst_ip} : Destination Port - {packet.dport} | Time | {packet_time} |")
                # Checks For Payload
                if Raw in packet:
                    print(f"Payload Data: {packet[Raw].load} ")
                else:
                    print("No Payload Detected")

            # Check For FTP Data channel
            elif packet[TCP].dport == 20 or packet[TCP].sport == 20:
                print(Style.BRIGHT + Fore.BLACK + Back.WHITE + f"Connection type [FTP] & IP Address | Source IP - {src_ip} : Source Port - {packet.sport} | Destination IP - {dst_ip} : Destination Port - {packet.dport} | Time | {packet_time} |")
                # Checks For Payload
                if Raw in packet:
                    print(f"Payload Data: {packet[Raw].load} ")
                else:
                    print("No Payload Detected")

            # Check For SMTP
            elif packet[TCP].dport == [25,465,587] or packet[TCP].sport == [25,465,587]:
                print(Style.BRIGHT + Fore.BLACK + Back.WHITE + f"Connection type [SMTP] & IP Address | Source IP - {src_ip} : Source Port - {packet.sport} | Destination IP - {dst_ip} : Destination Port - {packet.dport} | Time | {packet_time} |")
                # Checks For Payload
                if Raw in packet:
                    print(f"Payload Data: {packet[Raw].load} ")
                else:
                    print("No Payload Detected")

            # Check For POP3
            elif packet[TCP].dport == [110,995] or packet[TCP].sport == [110,995]:
                print(Style.BRIGHT + Fore.BLACK + Back.WHITE + f"Connection type [POP3] & IP Address | Source IP - {src_ip} : Source Port - {packet.sport} | Destination IP - {dst_ip} : Destination Port - {packet.dport} | Time | {packet_time} |")
                # Checks For Payload
                if Raw in packet:
                    print(f"Payload Data: {packet[Raw].load} ")
                else:
                    print("No Payload Detected")

            # Check For IMAP
            elif packet[TCP].dport == [143,993] or packet[TCP].sport == [143,993]:
                print(Style.BRIGHT + Fore.BLACK + Back.WHITE + f"Connection type [IMAP] & IP Address | Source IP - {src_ip} : Source Port - {packet.sport} | Destination IP - {dst_ip} : Destination Port - {packet.dport} | Time | {packet_time} |")
                # Checks For Payload
                if Raw in packet:
                    print(f"Payload Data: {packet[Raw].load} ")
                else:
                    print("No Payload Detected")

            # Check For Telnet
            elif packet[TCP].dport == 23 or packet[TCP].sport == 23:
                print(Style.BRIGHT + Fore.BLACK + Back.WHITE + f"Connection type [Telnet] & IP Address | Source IP - {src_ip} : Source Port - {packet.sport} | Destination IP - {dst_ip} : Destination Port - {packet.dport} | Time | {packet_time} |")
                # Checks For Payload
                if Raw in packet:
                    print(f"Payload Data: {packet[Raw].load} ")
                else:
                    print("No Payload Detected")

            # Check For SMB or Windows File Sharing
            elif packet[TCP].dport == [139,445] or packet[TCP].sport == [139,445]:
                print(Style.BRIGHT + Fore.BLACK + Back.WHITE + f"Connection type [SMB] & IP Address | Source IP - {src_ip} : Source Port - {packet.sport} | Destination IP - {dst_ip} : Destination Port - {packet.dport} | Time | {packet_time} |")
                # Checks For Payload
                if Raw in packet:
                    print(f"Payload Data: {packet[Raw].load} ")
                else:
                    print("No Payload Detected")

            # Check For Multimedia, But could be on another higher port
            elif packet[TCP].dport == 1024 or packet[TCP].sport == 1024:
                print(Style.BRIGHT + Fore.BLACK + Back.WHITE + f"Connection type [Multimedia] & IP Address | Source IP - {src_ip} : Source Port - {packet.sport} | Destination IP - {dst_ip} : Destination Port - {packet.dport} | Time | {packet_time} |")
                # Checks For Payload
                if Raw in packet:
                    print(f"Payload Data: {packet[Raw].load} ")
                else:
                    print("No Payload Detected")

            # TLS/SSL Encrypted Traffic also could house other traffic
            elif packet[TCP].dport == 443 or packet[TCP].sport == 443:
                print(Style.BRIGHT + Fore.BLACK + Back.WHITE + f"Connection type [TLS/SSL] & IP Address | Source IP - {src_ip} : Source Port - {packet.sport} | Destination IP - {dst_ip} : Destination Port - {packet.dport} | Time | {packet_time} |")
                # Checks For Payload
                if Raw in packet:
                    print(f"Payload Data: {packet[Raw].load} ")
                else:
                    print("No Payload Detected")

            # DNS Over TCP
            elif packet[TCP].dport == 53 or packet[TCP].sport == 53:
                print(Style.BRIGHT + Fore.BLACK + Back.WHITE + f"Connection type [DNS Over TCP] & IP Address | Source IP - {src_ip} : Source Port - {packet.sport} | Destination IP - {dst_ip} : Destination Port - {packet.dport} | Time | {packet_time} |")
                # Check if it's a DNS query or response
                if packet.haslayer(DNS):
                    dns_layer = packet[DNS]
                    # If It's a DNS Query
                    if dns_layer.qr == 0:
                        query_name = dns_layer[DNSQR].qname.decode()
                        query_type = dns_layer[DNSQR].qtype
                        print(f"DNS Query: {query_name} (Type: {query_type})")
                    # If It's a DNS Response
                    elif dns_layer.qr == 1:
                        # Check if there are any DNSRR (response) records
                        if dns_layer.haslayer(DNSRR):
                            for answer in dns_layer[DNSRR]:
                                print(f"DNS Response: {answer.rdata} (Type: {answer.type})")
                        else:
                            print("No DNS Response (No DNSRR records found)")
                    else:
                        print("No DNS layer found in the packet")

            # BGP A Routing Protocol
            elif packet[TCP].dport == 179 or packet[TCP].sport == 179:
                print(Style.BRIGHT + Fore.BLACK + Back.WHITE + f"Connection type [BGP] & IP Address | Source IP - {src_ip} : Source Port - {packet.sport} | Destination IP - {dst_ip} : Destination Port - {packet.dport} | Time | {packet_time} |")
                # Checks For Payload
                if Raw in packet:
                    print(f"Payload Data: {packet[Raw].load} ")
                else:
                    print("No Payload Detected")

            # VOIP UnEncrypted Channel and Encrypted
            elif packet[TCP].dport == [5060,5061] or packet[TCP].sport == [5060.5061]:
                print(Style.BRIGHT + Fore.BLACK + Back.WHITE + f"Connection type [VOIP] & IP Address | Source IP - {src_ip} : Source Port - {packet.sport} | Destination IP - {dst_ip} : Destination Port - {packet.dport} | Time | {packet_time} |")
                # Checks For Payload
                if Raw in packet:
                    print(f"Payload Data: {packet[Raw].load} ")
                else:
                    print("No Payload Detected")

            # MySQL Database queries
            elif packet[TCP].dport == 3306 or packet[TCP].sport == 3306:
                print(Style.BRIGHT + Fore.RED + Back.BLACK + f"Connection type [MySQL] & IP Address | Source IP - {src_ip} : Source Port - {packet.sport} | Destination IP - {dst_ip} : Destination Port - {packet.dport} | Time | {packet_time} |")
                # Checks For Payload
                if Raw in packet:
                    print(f"Payload Data: {packet[Raw].load} ")
                else:
                    print("No Payload Detected")

            # PostgreSQL Database queries
            elif packet[TCP].dport == 5432 or packet[TCP].sport == 5432:
                print(Style.BRIGHT + Fore.BLACK + Back.WHITE + f"Connection type [PostgreSQL] & IP Address | Source IP - {src_ip} : Source Port - {packet.sport} | Destination IP - {dst_ip} : Destination Port - {packet.dport} | Time | {packet_time} |")
                # Checks For Payload
                if Raw in packet:
                    print(f"Payload Data: {packet[Raw].load} ")
                else:
                    print("No Payload Detected")

            # XMPP Client Connections
            elif packet[TCP].dport == 5222 or packet[TCP].sport == 5222:
                print(Style.BRIGHT + Fore.BLACK + Back.WHITE + f"Connection type [XMPP-Client] & IP Address | Source IP - {src_ip} : Source Port - {packet.sport} | Destination IP - {dst_ip} : Destination Port - {packet.dport} | Time | {packet_time} |")
                # Checks For Payload
                if Raw in packet:
                    print(f"Payload Data: {packet[Raw].load} ")
                else:
                    print("No Payload Detected")

            # XMPP Server communication
            elif packet[TCP].dport == 5269 or packet[TCP].sport == 5269:
                print(Style.BRIGHT + Fore.BLACK + Back.WHITE + f"Connection type [XMPP-Server] & IP Address | Source IP - {src_ip} : Source Port - {packet.sport} | Destination IP - {dst_ip} : Destination Port - {packet.dport} | Time | {packet_time} |")
                # Checks For Payload
                if Raw in packet:
                    print(f"Payload Data: {packet[Raw].load} ")
                else:
                    print("No Payload Detected")

            # MQTT or IOT messaging UnEncrypted and Encrypted
            elif packet[TCP].dport == [1883,8883] or packet[TCP].sport == [1883,8883]:
                print(Style.BRIGHT + Fore.BLACK + Back.WHITE + f"Connection type [MQTT] & IP Address | Source IP - {src_ip} : Source Port - {packet.sport} | Destination IP - {dst_ip} : Destination Port - {packet.dport} | Time | {packet_time} |")
                # Checks For Payload
                if Raw in packet:
                    print(f"Payload Data: {packet[Raw].load} ")
                else:
                    print("No Payload Detected")

            # RDP - Remote Desktop Protocol
            elif packet[TCP].dport == 3389 or packet[TCP].sport == 3389:
                print(Style.BRIGHT + Fore.RED + Back.BLACK + f"Connection type [RDP] & IP Address | Source IP - {src_ip} : Source Port - {packet.sport} | Destination IP - {dst_ip} : Destination Port - {packet.dport} | Time | {packet_time} |")
                # Checks For Payload
                if Raw in packet:
                    print(f"Payload Data: {packet[Raw].load} ")
                else:
                    print("No Payload Detected")

            # Possible SSH Attack
            elif packet[TCP].dport == 22 or packet[TCP].sport == 22:
                print(Style.BRIGHT + Fore.RED + Back.BLACK + f"Connection type [SSH-ATK] & IP Address | Source IP - {src_ip} : Source Port - {packet.sport} | Destination IP - {dst_ip} : Destination Port - {packet.dport} | Time | {packet_time} |")
                # Checks For Payload
                if Raw in packet:
                    print(f"Payload Data: {packet[Raw].load} ")
                else:
                    print("No Payload Detected")

            # Possible Trojan or NetBIOS
            elif packet[TCP].dport == 138 or packet[TCP].sport == 138:
                print(Style.BRIGHT + Fore.RED + Back.BLACK + f"Connection type [netbios-dgm] & IP Address | Source IP - {src_ip} : Source Port - {packet.sport} | Destination IP - {dst_ip} : Destination Port - {packet.dport} | Time | {packet_time} |")
                # Checks For Payload
                if Raw in packet:
                    print(f"Payload Data: {packet[Raw].load} ")
                else:
                    print("No Payload Detected")

            # Any Other TCP Packets/General TCP
            else:
                print(Style.BRIGHT + Fore.BLACK + Back.WHITE + f"Connection type [TCP] & IP Address | Source IP - {src_ip} : Source Port - {packet.sport} | Destination IP - {dst_ip} : Destination Port - {packet.dport} | Time | {packet_time} |")
                if Raw in packet:
                    print(f"Raw Payload Data: {packet[Raw].load}")
                else:
                    print("No Payload Detected")

        # Checks UDP Packet
        if UDP in packet:

            # Session Initiation Protocol
            if packet[UDP].dport == [5060,5061] or packet[UDP].sport == [5060,5061]:
                print(Style.BRIGHT + Fore.YELLOW + Back.BLACK + f"Connection type [SIP] & IP Address | Source IP - {src_ip} : Source Port - {packet.sport} | Destination IP - {dst_ip} : Destination Port - {packet.dport} | Time | {packet_time} |")
                # Checks For Payload
                if Raw in packet:
                    print(f"Payload Data: {packet[Raw].load} ")
                else:
                    print("No Payload Detected")

            # RTSP Real Time Streaming Protocol
            elif packet[UDP].dport == 554 or packet[UDP].sport == 554:
                print(Style.BRIGHT + Fore.YELLOW + Back.BLACK + f"Connection type [RTSP] & IP Address | Source IP - {src_ip} : Source Port - {packet.sport} | Destination IP - {dst_ip} : Destination Port - {packet.dport} | Time | {packet_time} |")
                # Checks For Payload
                if Raw in packet:
                    print(f"Payload Data: {packet[Raw].load} ")
                else:
                    print("No Payload Detected")

            # TFTP Trivial File Transfer Protocol
            elif packet[UDP].dport == 69 or packet[UDP].sport == 69:
                print(Style.BRIGHT + Fore.YELLOW + Back.BLACK + f"Connection type [TFTP] & IP Address | Source IP - {src_ip} : Source Port - {packet.sport} | Destination IP - {dst_ip} : Destination Port - {packet.dport} | Time | {packet_time} |")
                # Checks For Payload
                if Raw in packet:
                    print(f"Payload Data: {packet[Raw].load} ")
                else:
                    print("No Payload Detected")

            # NFS Network File System
            elif packet[UDP].dport == 2049 or packet[UDP].sport == 2049:
                print(Style.BRIGHT + Fore.YELLOW + Back.BLACK + f"Connection type [NFS] & IP Address | Source IP - {src_ip} : Source Port - {packet.sport} | Destination IP - {dst_ip} : Destination Port - {packet.dport} | Time | {packet_time} |")
                # Checks For Payload
                if Raw in packet:
                    print(f"Payload Data: {packet[Raw].load} ")
                else:
                    print("No Payload Detected")

            # SNMP Simple Network Management Protocol Queries
            elif packet[UDP].dport == 161 or packet[UDP].sport == 161:
                print(Style.BRIGHT + Fore.YELLOW + Back.BLACK + f"Connection type [SNMP-Q] & IP Address | Source IP - {src_ip} : Source Port - {packet.sport} | Destination IP - {dst_ip} : Destination Port - {packet.dport} | Time | {packet_time} |")
                # Checks For Payload
                if Raw in packet:
                    print(f"Payload Data: {packet[Raw].load} ")
                else:
                    print("No Payload Detected")

            # SNMP Simple Network Management Protocol Traps
            elif packet[UDP].dport == 162 or packet[UDP].sport == 162:
                print(Style.BRIGHT + Fore.YELLOW + Back.BLACK + f"Connection type [SNMP-T] & IP Address | Source IP - {src_ip} : Source Port - {packet.sport} | Destination IP - {dst_ip} : Destination Port - {packet.dport} | Time | {packet_time} |")
                # Checks For Payload
                if Raw in packet:
                    print(f"Payload Data: {packet[Raw].load} ")
                else:
                    print("No Payload Detected")

            # LDAP Lightweight Directory Access Protocol
            elif packet[UDP].dport == 389 or packet[UDP].sport == 389:
                print(Style.BRIGHT + Fore.YELLOW + Back.BLACK + f"Connection type [SNMP-T] & IP Address | Source IP - {src_ip} : Source Port - {packet.sport} | Destination IP - {dst_ip} : Destination Port - {packet.dport} | Time | {packet_time} |")
                # Checks For Payload
                if Raw in packet:
                    print(f"Payload Data: {packet[Raw].load} ")
                else:
                    print("No Payload Detected")

            # Minecraft Server port could be different though or MCS
            elif packet[UDP].dport == [19132,25565] or packet[UDP].sport == [19132,25565]:
                print(Style.BRIGHT + Fore.YELLOW + Back.BLACK + f"Connection type [MCS] & IP Address | Source IP - {src_ip} : Source Port - {packet.sport} | Destination IP - {dst_ip} : Destination Port - {packet.dport} | Time | {packet_time} |")
                # Checks For Payload
                if Raw in packet:
                    print(f"Payload Data: {packet[Raw].load} ")
                else:
                    print("No Payload Detected")

            # Steam Games Traffic or SGT
            elif packet[UDP].dport == [27015] or packet[UDP].sport == [27015]:
                print(Style.BRIGHT + Fore.YELLOW + Back.BLACK + f"Connection type [SGT] & IP Address | Source IP - {src_ip} : Source Port - {packet.sport} | Destination IP - {dst_ip} : Destination Port - {packet.dport} | Time | {packet_time} |")
                # Checks For Payload
                if Raw in packet:
                    print(f"Payload Data: {packet[Raw].load} ")
                else:
                    print("No Payload Detected")

            # DHCP Dynamic Host Configuration Protocol - Server
            elif packet[UDP].dport == 67 or packet[UDP].sport == 67:
                print(Style.BRIGHT + Fore.YELLOW + Back.BLACK + f"Connection type [DHCP-S] & IP Address | Source IP - {src_ip} : Source Port - {packet.sport} | Destination IP - {dst_ip} : Destination Port - {packet.dport} | Time | {packet_time} |")
                # Checks For Payload
                if Raw in packet:
                    print(f"Payload Data: {packet[Raw].load} ")
                else:
                    print("No Payload Detected")

            # DHCP Dynamic Host Configuration Protocol - Client
            elif packet[UDP].dport == 68 or packet[UDP].sport == 68:
                print(Style.BRIGHT + Fore.YELLOW + Back.BLACK + f"Connection type [DHCP-C] & IP Address | Source IP - {src_ip} : Source Port - {packet.sport} | Destination IP - {dst_ip} : Destination Port - {packet.dport} | Time | {packet_time} |")
                # Checks For Payload
                if Raw in packet:
                    print(f"Payload Data: {packet[Raw].load} ")
                else:
                    print("No Payload Detected")

            # SysLog
            elif packet[UDP].dport == 514 or packet[UDP].sport == 514:
                print(Style.BRIGHT + Fore.YELLOW + Back.BLACK + f"Connection type [SysLog] & IP Address | Source IP - {src_ip} : Source Port - {packet.sport} | Destination IP - {dst_ip} : Destination Port - {packet.dport} | Time | {packet_time} |")
                # Checks For Payload
                if Raw in packet:
                    print(f"Payload Data: {packet[Raw].load} ")
                else:
                    print("No Payload Detected")

            # RADIUS or Remote Authentication Dial-In User Service Authentication
            elif packet[UDP].dport == 1812 or packet[UDP].sport == 1812:
                print(Style.BRIGHT + Fore.YELLOW + Back.BLACK + f"Connection type [SysLog] & IP Address | Source IP - {src_ip} : Source Port - {packet.sport} | Destination IP - {dst_ip} : Destination Port - {packet.dport} | Time | {packet_time} |")
                # Checks For Payload
                if Raw in packet:
                    print(f"Payload Data: {packet[Raw].load} ")
                else:
                    print("No Payload Detected")

            # RADIUS or Remote Authentication Dial-In User Service Accounting
            elif packet[UDP].dport == 1813 or packet[UDP].sport == 1813:
                print(Style.BRIGHT + Fore.YELLOW + Back.BLACK + f"Connection type [RADIUS] & IP Address | Source IP - {src_ip} : Source Port - {packet.sport} | Destination IP - {dst_ip} : Destination Port - {packet.dport} | Time | {packet_time} |")
                # Checks For Payload
                if Raw in packet:
                    print(f"Payload Data: {packet[Raw].load} ")
                else:
                    print("No Payload Detected")

            # WhatsApp Services or WhP
            elif packet[UDP].dport == [5222,3478] or packet[UDP].sport == [5222,3478]:
                print(Style.BRIGHT + Fore.YELLOW + Back.BLACK + f"Connection type [WhP] & IP Address | Source IP - {src_ip} : Source Port - {packet.sport} | Destination IP - {dst_ip} : Destination Port - {packet.dport} | Time | {packet_time} |")
                # Checks For Payload
                if Raw in packet:
                    print(f"Payload Data: {packet[Raw].load} ")
                else:
                    print("No Payload Detected")

            # NTP or Network Time Protocol
            elif packet[UDP].dport == 123 or packet[UDP].sport == 123:
                print(Style.BRIGHT + Fore.YELLOW + Back.BLACK + f"Connection type [NTP] & IP Address | Source IP - {src_ip} : Source Port - {packet.sport} | Destination IP - {dst_ip} : Destination Port - {packet.dport} | Time | {packet_time} |")
                # Checks For Payload
                if Raw in packet:
                    print(f"Payload Data: {packet[Raw].load} ")
                else:
                    print("No Payload Detected")

            # UPnP or Universal Plug and Play
            elif packet[UDP].dport == 1900 or packet[UDP].sport == 1900:
                print(Style.BRIGHT + Fore.YELLOW + Back.BLACK + f"Connection type [UPnP] & IP Address | Source IP - {src_ip} : Source Port - {packet.sport} | Destination IP - {dst_ip} : Destination Port - {packet.dport} | Time | {packet_time} |")
                # Checks For Payload
                if Raw in packet:
                    print(f"Payload Data: {packet[Raw].load} ")
                else:
                    print("No Payload Detected")

            # Spotify Streaming or SSG
            elif packet[UDP].dport == 4070 or packet[UDP].sport == 4070:
                print(Style.BRIGHT + Fore.YELLOW + Back.BLACK + f"Connection type [SSG] & IP Address | Source IP - {src_ip} : Source Port - {packet.sport} | Destination IP - {dst_ip} : Destination Port - {packet.dport} | Time | {packet_time} |")
                # Checks For Payload
                if Raw in packet:
                    print(f"Payload Data: {packet[Raw].load} ")
                else:
                    print("No Payload Detected")

            # Multicast DNS or mDNS
            elif packet[UDP].dport == 5353 or packet[UDP].sport == 5353:
                print(Style.BRIGHT + Fore.YELLOW + Back.BLACK + f"Connection type [mDNS] & IP Address | Source IP - {src_ip} : Source Port - {packet.sport} | Destination IP - {dst_ip} : Destination Port - {packet.dport} | Time | {packet_time} |")
                # Checks For Payload
                if Raw in packet:
                    print(f"Payload Data: {packet[Raw].load} ")
                else:
                    print("No Payload Detected")

            # HTTPS on UDP
            elif packet[UDP].dport == 443 or packet[UDP].sport == 443:
                print(Style.BRIGHT + Fore.YELLOW + Back.BLACK + f"Connection type [HTTPS] & IP Address | Source IP - {src_ip} : Source Port - {packet.sport} | Destination IP - {dst_ip} : Destination Port - {packet.dport} | Time | {packet_time} |")
                # Checks For Payload
                if Raw in packet:
                    print(f"Payload Data: {packet[Raw].load} ")
                else:
                    print("No Payload Detected")

            # Possible Trojan or NetBIOS
            elif packet[UDP].dport == 138 or packet[UDP].sport == 138:
                print(Style.BRIGHT + Fore.RED + Back.BLACK + f"Connection type [netbios-dgm] & IP Address | Source IP - {src_ip} : Source Port - {packet.sport} | Destination IP - {dst_ip} : Destination Port - {packet.dport} | Time | {packet_time} |")
                # Checks For Payload
                if Raw in packet:
                    print(f"Payload Data: {packet[Raw].load} ")
                else:
                    print("No Payload Detected")

            # alljoyn
            elif packet[UDP].dport == 9956 or packet[UDP].sport == 9956:
                print(Style.BRIGHT + Fore.YELLOW + Back.BLACK + f"Connection type [alljoyn] & IP Address | Source IP - {src_ip} : Source Port - {packet.sport} | Destination IP - {dst_ip} : Destination Port - {packet.dport} | Time | {packet_time} |")
                # Checks For Payload
                if Raw in packet:
                    print(f"Payload Data: {packet[Raw].load} ")
                else:
                    print("No Payload Detected")

            # HTTP
            elif packet[UDP].dport == 80 or packet[UDP].sport == 80:
                print(Style.BRIGHT + Fore.YELLOW + Back.BLACK + f"Connection type [alljoyn] & IP Address | Source IP - {src_ip} : Source Port - {packet.sport} | Destination IP - {dst_ip} : Destination Port - {packet.dport} | Time | {packet_time} |")
                # Checks For Payload
                if Raw in packet:
                    print(f"Payload Data: {packet[Raw].load} ")
                else:
                    print("No Payload Detected")

            # Checks For DNS
            elif packet[UDP].dport == 53 or packet[UDP].sport == 53:
                print(Style.BRIGHT + Fore.YELLOW + Back.BLACK + f"Connection type [DNS] & IP Address | Source IP - {src_ip} : Source Port - {packet.sport} | Destination IP - {dst_ip} : Destination Port - {packet.dport} | Time | {packet_time} |")
                # Check if it's a DNS query or response
                if packet.haslayer(DNS):
                    dns_layer = packet[DNS]
                    # If It's a DNS Query
                    if dns_layer.qr == 0:
                        query_name = dns_layer[DNSQR].qname.decode()
                        query_type = dns_layer[DNSQR].qtype
                        print(f"DNS Query: {query_name} (Type: {query_type})")
                    # If It's a DNS Response
                    elif dns_layer.qr == 1:
                        # Check if there are any DNSRR (response) records
                        if dns_layer.haslayer(DNSRR):
                            for answer in dns_layer[DNSRR]:
                                print(f"DNS Response: {answer.rdata} (Type: {answer.type})")
                        else:
                            print("No DNS Response (No DNSRR records found)")
                    else:
                        print("No DNS layer found in the packet")
            # General UDP Connections
            else:
                print(Style.BRIGHT + Fore.YELLOW + Back.BLACK + f"Connection type [UDP] & IP Address | Source IP - {src_ip} : Source Port - {packet.sport} | Destination IP - {dst_ip} : Destination Port - {packet.dport} | Time | {packet_time} |")
                if Raw in packet:
                    print(f"Raw Payload Data: {packet[Raw].load}")
                else:
                    print("No Payload Detected")
        # ICMP packets
        elif ICMP in packet:
            print(Style.BRIGHT + Fore.BLACK + Back.BLUE + f"Connection type [ICMP] & IP Address | Source IP - {src_ip} | Destination IP - {dst_ip} | Time | {packet_time} |")
            if Raw in packet:
                print(f"Payload Data: {packet[ICMP].load} ")
            else:
                print("No Payload Detected")


def packet_handler(packet):

    # Checking if there is a IP layer
    if packet.haslayer('IP'):
        ip_src = packet['IP'].src
        ip_dst = packet['IP'].dst

        # Filters out all ips and traffic except the target IP
        if ip_src == target_ip or ip_dst == target_ip:
            monitor(packet)

def port_handler(packet):

    # Check if there is a IP layer first
    if packet.haslayer(IP):

        ip_src = packet[IP].src
        ip_dst = packet[IP].dst

        # Checks if TCP is there if not goes to the next statement
        if packet.haslayer(TCP):
            portsrctcp = packet[TCP].sport
            portdsttcp = packet[TCP].dport

            if portsrctcp == target_port or portdsttcp == target_port:
                monitor(packet)
        # Checks for UDP
        elif packet.haslayer(UDP):
            portsrcudp = packet[UDP].sport
            portdsudp = packet[UDP].dport

            if portdsudp == target_port or portsrcudp == target_port:
                monitor(packet)

def portip_handler(packet):

    if packet.haslayer('IP'):
        ip_src = packet['IP'].src
        ip_dst = packet['IP'].dst

        # Gets only the target IP
        if ip_src == target_ip or ip_dst == target_ip:

            # Filters out all ports except the target port
            if packet.haslayer(TCP):
                portsrctcp = packet[TCP].sport
                portdsttcp = packet[TCP].dport

                if portsrctcp == target_port or portdsttcp == target_port:
                    monitor(packet)

            elif packet.haslayer(UDP):
                portsrcudp = packet[UDP].sport
                portdsudp = packet[UDP].dport

                if portdsudp == target_port or portsrcudp == target_port:
                    monitor(packet)

ip_packet_count = defaultdict(lambda: {'count': 0, 'last_seen': time.time()})
threshold = 2500  # Threshold for DoS/DDos detection 2500 is the Standard Threshold

# Dos/DDos Detector
def dos_handler(packet):

    global ip_packet_count

    if packet.haslayer('IP'):
        ip_src = packet['IP'].src
        interface = conf.iface
        localmachine = get_if_addr(interface)

        if ip_src != localmachine:
            # Check if the source IP has been seen before
            current_time = time.time()
            if ip_src in ip_packet_count:
                # If the time difference is more than 60 seconds, reset the count
                time_diff = current_time - ip_packet_count[ip_src]['last_seen']
                if time_diff > 60:  # 1 minute window
                    ip_packet_count[ip_src]['count'] = 0
                    print("\nNo Dos/DDos Attack Detected Counter Reset")

            # Increment the packet count for the source IP
            ip_packet_count[ip_src]['count'] += 1
            ip_packet_count[ip_src]['last_seen'] = current_time

            # Check if the count exceeds the threshold
            if ip_packet_count[ip_src]['count'] >= threshold:
                sys.stdout.write("\r" + Back.BLACK + Fore.RED +f"[ALERT] Possible DoS/DDoS attack from IP: {ip_src} | Requests: {ip_packet_count[ip_src]['count']} "+ Style.RESET_ALL)
                sys.stdout.flush()


def monitor_traffic():
    print("Starting network traffic monitoring...")
    sniff(prn=monitor, filter="tcp or udp or icmp or ip", store=0)

if __name__ == "__main__":
    # Gets the Terminal width to adjust the location of the text
    terminal_width = shutil.get_terminal_size().columns
    print("Vigil".center(terminal_width, '-') + "\n")
    print("What would you like to monitor?".center(terminal_width, ' '))
    print("| 1:All Traffic |".center(terminal_width, ' '))
    print("| 2:Specific IP Address |".center(terminal_width, ' '))
    print("| 3:Specific Port |".center(terminal_width, ' '))
    print("| 4.Specific port & IP Address |".center(terminal_width, ' '))
    print("| 5.Check For DDos/Dos Attacks |\n".center(terminal_width, ' '))
    print("|Credits/Developers : Qais M.Alqaissi & Noor A.Jaber|\n".center(terminal_width, ' '))
    print("|Vigil Main Terminal|".center(terminal_width, '-')+"\n")

    In = input("Enter The Number of your choice: ")

    if In == "1":
        monitor_traffic()
    elif In == "2":
        target_ip = input("Enter the IP Address to monitor: ").strip()
        sniff(prn=packet_handler, store=0)
    elif In == "3":
        target_port = int(input("Enter the Port Number to monitor: "))
        sniff(prn=port_handler, store=0)
    elif In == "4":
        target_ip = input("Enter the IP Address to monitor: ").strip()
        target_port = int(input("Enter the Port Number to monitor: "))
        sniff(prn=portip_handler, store=0)
    elif In == "5":
        sniff(prn=dos_handler, store=0)
