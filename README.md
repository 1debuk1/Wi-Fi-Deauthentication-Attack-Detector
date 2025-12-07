**Wi-Fi Deauthentication Attack Detector**
A lightweight, Python-based network security tool designed to detect 802.11 Deauthentication (Deauth) attacks in real-time. This script utilizes the scapy library to sniff Wi-Fi management frames and identifies potential Denial-of-Service (DoS) attempts based on customizable thresholds.

🚀 Overview
Deauthentication attacks are a common method used to disconnect users from a Wi-Fi network. They work by spoofing "Type 0 / Subtype 12" management frames, forcing the target device to drop its connection.

This tool monitors a wireless interface in Monitor Mode, tracks the frequency of deauth packets from specific MAC addresses, and triggers an alert if the traffic pattern resembles an attack (flooding).

✨ Features
Real-time Sniffing: Captures raw 802.11 packets using Scapy.

Packet Filtering: Specifically filters for Dot11Deauth layers (Management Frame, Subtype 12).

Threshold Detection: Distinguishes between normal network maintenance and an attack using a time-window algorithm.

Customizable parameters: easy to adjust sensitivity (Threshold & Time Window).

Detailed Alerts: console output provides the attacker's Source MAC and attack intensity.

🛠️ Prerequisites
Before running this tool, ensure you have the following:

Python 3.x

Scapy Library:

Bash

pip install scapy
Wi-Fi Adapter with Monitor Mode: You need a network card capable of packet injection/monitor mode (e.g., Atheros AR9271, various Alfa cards).

Root Privileges: Sniffing network traffic requires sudo.

⚙️ Configuration
Open wifi_deauth_detect.py and adjust the configuration variables at the top of the file to match your environment:

Python

MONITOR_INTERFACE = "wlan1mon" # The name of your interface in monitor mode
DEAUTH_THRESHOLD = 5           # Number of frames required to trigger an alert
TIME_WINDOW = 5                # Time window (in seconds) to count the frames
📥 Installation & Usage
Clone the repository:

Bash

git clone https://github.com/1debuk1/Wi-Fi-Deauthentication-Attack-Detector.git
cd wifi-deauth-detector
Enable Monitor Mode (on Linux/Kali):

Bash

sudo airmon-ng start wlan0
# Note the name of the new interface (usually wlan0mon or wlan1mon)
Run the detector:

Bash

sudo python3 wifi_deauth_detect.py
🧠 How It Works
The script defines a packet_handler callback function that executes for every packet sniffed:

Layer Check: It verifies if the packet is an 802.11 Management frame with a Deauthentication subtype.

Source Tracking: It extracts the Sender MAC address (addr2).

Logic Logic:

It records the timestamp of the packet.

If a previous packet from the same MAC was seen longer than TIME_WINDOW seconds ago, the counter resets (assuming normal traffic).

If the packet arrives within the window, the counter increments.

Alerting: If the counter hits DEAUTH_THRESHOLD, a warning is printed to the console indicating a potential flood attack.
