Network Packet Analyzer
Overview
This is a Network Packet Sniffer tool developed as part of Task 5 for Prodigy Infotech. The tool is built using Python and the scapy library. It captures and analyzes network packets, displaying important details such as the source IP, destination IP, protocols, and payload data.

This project emphasizes ethical network monitoring and is intended solely for educational and research purposes.

Features
Captures network traffic in real-time.
Displays source and destination IP addresses.
Identifies and displays protocol information (TCP, UDP, ICMP).
Provides payload details for TCP/UDP packets.
Requirements
Python 3.x
scapy library

Installation
Clone this repository:

```bash
git clone https://github.com/prithul21/packet_sniffer.git
```
Install the required Python packages:

```bash
pip install scapy
```
Usage
Open the terminal in the project directory.
Run the Python script:
```bash
python packet_sniffer.py
```
If you are on Linux/macOS, you may need to use sudo:
```bash
sudo python packet_sniffer.py
```

Replace the default network interface in the script with the one relevant to your system (e.g., Ethernet 3).
Example Output
```yaml
Source IP: 192.168.68.239
Destination IP: 192.168.68.110
Protocol: TCP
Payload: b'\x16\x03\x01\x00\x8a\x01\x00\x00\x86\x03\x03'
```
Ethical Usage
Disclaimer:
This tool is developed solely for educational and research purposes. Unauthorized network sniffing or monitoring of any network traffic without explicit permission is illegal and unethical. Make sure you only use this tool on networks where you have legal authorization to do so.
