import scapy.all as scapy
import optparse

def get_argument():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="target", help="Target IP / IP range.")
    (options, arguments) = parser.parse_args()
    return options

def scan(ip):
    # scapy.arping(ip)
    arp_request = scapy.ARP(pdst=ip)
    # arp_request.show()
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    # broadcast.show()
    arp_request_broadcast = broadcast / arp_request
    # arp_request_broadcast.show()
    answered_list, unanswered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)
    # print("IP\t\t\t\tMAC Address\n-------------------------------------")
    client_list = []
    for element in answered_list:
        client_dict = {"IP": element[1].psrc, "Mac": element[1].hwsrc}
        client_list.append(client_dict)
    return client_list
    # print(arp_request.summary())
    # scapy.ls(scapy.ARP())


def print_result(result_list):
    print("IP\t\t\t\tMAC address\n-------------------------------------------------------")
    for client in result_list:
        print(client["IP"] + "\t\t\t" + client["Mac"])

options = get_argument()
# scan_result = scan("192.168.137.1/24")
scan_result = scan(options.target)
print_result(scan_result)
