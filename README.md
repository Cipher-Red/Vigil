# Vigil - Network Traffic Monitor

**Vigil** is a lightweight Python-based network traffic monitoring tool designed to capture and analyze live network traffic. It supports real-time packet inspection, protocol identification, IP/port monitoring, and basic detection of DoS/DDoS attacks. Vigil saves captured packets in the PCAP file format for further analysis and is cross-platform, working on both Linux and Windows systems.

---

## Features

- **Live Traffic Capture**: Monitor and capture live network traffic in real-time.
- **Protocol Identification**: Detect and classify packets by protocol (e.g., TCP, UDP, ICMP, HTTP, HTTPS, DNS, etc.).
- **IP and Port Monitoring**: Filter traffic by specific IP addresses or ports.
- **DoS/DDoS Detection**: Identify potential DoS/DDoS attacks based on traffic patterns.
- **Payload Inspection**: Display payload data for packets (if available).
- **PCAP File Export**: Save captured packets in PCAP format for analysis with tools like Wireshark.
- **Cross-Platform Support**: Works on both Linux and Windows operating systems.

---

## Installation

### Prerequisites

1. **Python 3.6 or higher**: Ensure Python is installed on your system.
   - Download Python: [https://www.python.org/downloads/](https://www.python.org/downloads/)

2. **Install Required Libraries**:
   - Install the required Python libraries using pip:
     ```bash
     pip install scapy colorama
     ```

3. **Install Npcap (Windows Only)**:
   - On Windows, install **Npcap** (a replacement for WinPcap) to enable packet capturing.
   - Download Npcap: [https://npcap.com/](https://npcap.com/)

---

## Usage

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/Cipher-Red/vigil.git
   cd vigil
   ```

2. **Run the Script**:
   - Run the script with the following command:
     ```bash
     python vigil.py
     ```

3. **Select Monitoring Mode**:
   - The script will prompt you to choose a monitoring mode:
     ```
     What would you like to monitor?
     | 1:All Traffic |
     | 2:Specific IP Address |
     | 3:Specific Port |
     | 4.Specific port & IP Address |
     | 5.Check For DDos/Dos Attacks |
     ```
   - Enter the number corresponding to your desired mode.

4. **Provide Input (if required)**:
   - For modes 2, 3, and 4, you will be prompted to enter:
     - **IP Address**: The specific IP address to monitor.
     - **Port Number**: The specific port to monitor.

5. **Review Output**:
   - Vigil will display live traffic details, including:
     - Source and destination IP addresses.
     - Source and destination ports.
     - Packet protocol (e.g., HTTP, HTTPS, DNS, etc.).
     - Payload data (if available).
   - Captured packets are saved in `captured_traffic.pcap` for further analysis.

---

## Example Use Cases

1. **Monitor All Traffic**:
   - Choose option `1` to capture all traffic on the network interface.

2. **Monitor Traffic for a Specific IP Address**:
   - Choose option `2` and enter the target IP address (e.g., `192.168.1.100`).

3. **Monitor Traffic for a Specific Port**:
   - Choose option `3` and enter the target port (e.g., `80` for HTTP).

4. **Monitor Traffic for a Specific IP and Port**:
   - Choose option `4` and enter both the IP address and port (e.g., `192.168.1.100` and `443`).

5. **Detect DoS/DDoS Attacks**:
   - Choose option `5` to monitor for potential DoS/DDoS attacks based on packet frequency.

---

## Supported Protocols

Vigil identifies and classifies traffic for the following protocols:

- **TCP**: HTTP, HTTPS, FTP, SMTP, POP3, IMAP, SSH, Telnet, MySQL, PostgreSQL, RDP, etc.
- **UDP**: DNS, DHCP, SNMP, NTP, SIP, TFTP, etc.
- **ICMP**: Ping requests and responses.
- **Other**: Custom port-based traffic classification.

---

## Credits/Developers

Vigil was developed by:
- **Qais M. Alqaissi** Portfolio Link: https://qaisalqaissi.netlify.app
- **Noor A. Jaber** Portfolio Link: https://noorjaber.netlify.app

We would like to acknowledge the contributions of the open-source community and the tools that made this project possible.

---

## Contributing

Contributions are welcome! If you'd like to improve Vigil, please follow these steps:

1. Fork the repository.
2. Create a new branch for your feature or bugfix.
3. Commit your changes.
4. Submit a pull request.

---

## License

This project is licensed under the **Apache License 2.0**. See the [LICENSE](LICENSE) file for details.

---

## Acknowledgments

- **Scapy**: The powerful Python library used for packet manipulation and analysis.
- **Colorama**: For adding colored output to the terminal.
- **Npcap**: For providing packet capture capabilities on Windows.

---

## Support

If you encounter any issues or have questions, please open an issue on the [GitHub repository](https://github.com/yourusername/vigil/issues).

---

### Apache License 2.0 Summary

The **Apache License 2.0** allows you to freely use, modify, and distribute the software, provided that you include the original copyright notice and disclaimers. It also provides a patent grant, protecting users from patent claims by contributors. For the full license text, see [LICENSE](LICENSE).
