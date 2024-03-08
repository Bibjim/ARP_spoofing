import logging
from scapy.all import sniff, ARP
from datetime import datetime
import argparse
import os

# Configuration du fichier de log
LOG_FILE = "arp_spoofing_log.txt"
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format='%(asctime)s %(message)s')

# Arguments de ligne de commande
parser = argparse.ArgumentParser(description="ARP Spoofing Detection Tool")
parser.add_argument("-i", "--interface", help="Specify the network interface to monitor", required=True)
args = parser.parse_args()

# Liste de confiance des associations IP-MAC
TRUSTED_IP_MAC = {}


def detect_arp_spoofing(packet):
    if ARP in packet and packet[ARP].op in (1, 2):  # ARP request or reply
        src_ip = packet[ARP].psrc
        src_mac = packet[ARP].hwsrc

        if src_ip in TRUSTED_IP_MAC:
            if TRUSTED_IP_MAC[src_ip] != src_mac:
                alert_msg = f"ALERT: Possible ARP Spoofing detected! IP {src_ip} is associated with {src_mac} instead of {TRUSTED_IP_MAC[src_ip]}"
                print(alert_msg)
                logging.warning(alert_msg)
        else:
            TRUSTED_IP_MAC[src_ip] = src_mac
            info_msg = f"Trusted association added: IP {src_ip} is associated with MAC {src_mac}"
            print(info_msg)
            logging.info(info_msg)


def main():
    print(f"Monitoring for ARP packets on {args.interface}. Press CTRL+C to stop.")
    try:
        sniff(iface=args.interface, prn=detect_arp_spoofing, store=0)
    except Exception as e:
        logging.error(f"Error: {e}")
        print(f"An error occurred: {e}")


if __name__ == "__main__":
    main()