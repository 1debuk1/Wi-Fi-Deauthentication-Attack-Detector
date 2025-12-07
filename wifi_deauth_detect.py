import sys
from scapy.all import sniff, Dot11, Dot11Deauth, listen

MONITOR_INTERFACE = "wlan1mon" 

DEAUTH_THRESHOLD = 5 
TIME_WINDOW = 5        #time in sec, 

deauth_frames = {} 

def packet_handler(packet):
    if packet.haslayer(Dot11):            # Scapy= direct check for the Dot11Deauth layer
        if packet.haslayer(Dot11Deauth):
           
            sender_mac = packet.addr2
            current_time = packet.time               # Scapy packet time (float)

            print(f"[*] DEAUTH frame detected from: {sender_mac} at {current_time:.2f}")
            if sender_mac not in deauth_frames:
                deauth_frames[sender_mac] = {'count': 0, 'timestamp': current_time}

            if (current_time - deauth_frames[sender_mac]['timestamp']) > TIME_WINDOW:
                deauth_frames[sender_mac]['count'] = 1
                deauth_frames[sender_mac]['timestamp'] = current_time
            else:
                deauth_frames[sender_mac]['count'] += 1

            #flood/attack condition
            current_count = deauth_frames[sender_mac]['count']
            if current_count >= DEAUTH_THRESHOLD:
                print("\n" + "#" * 50)
                print(f"!!! DE-AUTH ATTACK ALERT !!!")
                print(f"  Source MAC: {sender_mac}")
                print(f"  Reason: {current_count} de-auth frames detected in {TIME_WINDOW} seconds.")
                print(f"  Action: You are likely being targeted by a denial-of-service attack.")
                print("#" * 50 + "\n")
def run_detector():
    try:
        print(f"[*] Starting Wi-Fi De-auth Detector on interface: {MONITOR_INTERFACE}")
        print(f"[*] Threshold: {DEAUTH_THRESHOLD} frames in {TIME_WINDOW} seconds.")
        print("--- Press Ctrl+C to stop ---")

        sniff(iface=MONITOR_INTERFACE, prn=packet_handler, store=0)

    except KeyboardInterrupt:
        print("\n[*] Detector stopped by user.")
        sys.exit(0)
    except OSError as e:
        print(f"\n[!!!] Error: {e}")
        print(f"[!!!] Ensure '{MONITOR_INTERFACE}' is the correct interface name and is in Monitor Mode.")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!!!] An unexpected error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    run_detector()
