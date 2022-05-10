import scapy.all as scapy
import argparse
import sys


def get_ip():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="IP address or Subnet to scan. Use --help for more information")
    options = parser.parse_args()
    if not options.target:
        print("[-]Error. No target specified")
        sys.exit()
    return options


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    (answered, unanswered) = scapy.srp(arp_request_broadcast, timeout=1)
    client_list = []
    for element in answered:
        client = {
            "ip": element[1].psrc,
            "mac": element[1].hwsrc
        }
        client_list.append(client)
    return client_list


def print_results(result_list):
    print('_' * 50)
    print('IP\t\t\tMAC')
    print('-' * 50)
    for client in result_list:
        print(client["ip"] + "\t\t" + client["mac"])


options = get_ip()
scan_result = scan(options.target)
print_results(scan_result)

