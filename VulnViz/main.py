#!/./venv/bin/python
import concurrent
import concurrent.futures
import json
import os
import subprocess
import sys
import time
from shutil import copy2

import netifaces
import pyshark
from art import *
from libnmap.parser import NmapParser
from libnmap.parser import NmapParserException
from libnmap.process import NmapProcess


class Node:
    def __init__(self, ip_addr, hostname):
        self.ip_addr = ip_addr
        self.host_name = hostname
        self.data = []
        self.jsonDict = ""
        self.link = ""
        self.vulnerable = False

    def add_data_compromised(self, port, protocol, service):
        self.vulnerable = True
        self.data.append({"port": port,
                          "protocol": protocol,
                          "service": service
                          })

    def create_json_dict(self):
        if self.vulnerable:
            self.jsonDict = {'id': self.ip_addr,
                             'label': self.host_name,
                             'properties': {
                                 "open-ports": True,
                                 "data": self.data}}
        else:
            self.jsonDict = {'id': self.ip_addr,
                             'label': self.host_name,
                             'properties': self.data}


def host_scan(target):
    parsed = None
    nmproc = NmapProcess(target, options="-sn")
    nmproc.start()
    while nmproc.is_running():
        string = f"Host scan running... {nmproc.progress}% completed"
        sys.stdout.write("\r" + string)
        time.sleep(0.1)
    print("\rHost scan completed\n")
    try:
        parsed = NmapParser.parse(nmproc.stdout)
    except NmapParserException as e:
        print(f"Scan exception: {e}")
    hosts = []
    for host in parsed.hosts:
        if host.is_up():
            print(host.hostnames)
            hosts.append(host.address)
    return hosts


def full_scan(host):
    fullscan = NmapProcess(host, options="-T5 --top-ports 500")
    fullscan.start()
    print(f"Performing full scan of {host}\n")
    while fullscan.is_running():
        time.sleep(0.1)
    print(f"\nFull scan of {host} completed.")
    try:
        full_data = NmapParser.parse(fullscan.stdout)
        return full_data.hosts[0]
    except NmapParserException as e:
        print(f"Scan exception: {e}")


def main_node_creation(host):
    print(host.hostnames)
    if len(host.hostnames) != 0:
        new_node = Node(host.address, host.hostnames[0])
    else:
        new_node = Node(host.address, host.address)
    for id in host.get_open_ports():
        service = host.get_service(id[0], id[1])
        cpe_list = service.cpelist
        if len(cpe_list) == 0:
            new_node.add_data_compromised(id[0], id[1], service.service)
    return new_node


def prep_json(target):
    if os.path.exists("scripts/nodes.json"):
        os.remove("scripts/nodes.json")
    prep_dict = {'type': "NetworkGraph",
                 'protocol': "static",
                 'version': "null",
                 'metric': "null",
                 'label': target,
                 'nodes': [],
                 'links': []
                 }
    jsonString = json.dumps(prep_dict)
    json_file = open("scripts/nodes.json", "w")
    json_file.write(jsonString)
    json_file.close()


def nodes_to_json(nodes):
    with open("scripts/nodes.json", "r+") as f:
        file_data = json.load(f)
        for node in nodes:
            node.create_json_dict()
            file_data["nodes"].append(node.jsonDict)
            f.seek(0)
        json.dump(file_data, f, indent=4)
        f.close()


def quick_scan(host):
    scan = NmapProcess(host, options="-T5 --top-ports 50")
    scan.start()
    print(f"Performing scan of {host}\n")
    while scan.is_running():
        time.sleep(0.1)
    print(f"\nScan of {host} completed.")
    try:
        data = NmapParser.parse(scan.stdout)
        return data.hosts[0]
    except NmapParserException as e:
        print(f"Scan exception: {e}")


def continuous_packet_sniff(main_nodes):
    interfaces = netifaces.interfaces()
    return_nodes = []
    all_ips = []
    for node in main_nodes:
        all_ips.append(node.ip_addr)
    start = time.time()
    capture = pyshark.LiveCapture(interface=interfaces, use_json=True)
    for packet in capture.sniff_continuously():
        if time.time() - start > 60:
            break
        else:
            try:
                sniffed_ips = []
                link_list = []
                ip_src = packet['IP'].src
                ip_dst = packet['IP'].dst
                sniffed_ips.append(ip_src)
                sniffed_ips.append(ip_dst)
                for ip in sniffed_ips:
                    if ip not in all_ips:
                        all_ips.append(ip)
                        new_node = Node(ip, str(ip))
                        return_nodes.append(new_node)
                        scanned_node = quick_scan(new_node.ip_addr)
                        main_node = main_node_creation(scanned_node)
                        with open("scripts/nodes.json", "r+") as f:
                            file_data = json.load(f)
                            main_node.create_json_dict()
                            file_data["nodes"].append(main_node.jsonDict)
                            f.seek(0)
                            json.dump(file_data, f, indent=4)
                            f.close()
                copy2("scripts/nodes.json", "static/netjsongraph.js/data")
                links = []
                check = ip_dst + " " + ip_src
                check2 = ip_src + " " + ip_dst
                if check not in link_list:
                    if check2 not in link_list:
                        link_list.append(check)
                link_type = ""
                if packet.highest_layer == "TCP":
                    link_type = "TCP"
                elif packet.highest_layer == "TLS":
                    link_type = "TLS"
                elif packet.highest_layer in ["DHCP", "DATA", "NBNS", "MDNS", "SSDP", "LLMNR"]:
                    link_type = "UDP"
                elif packet.highest_layer == "ARP":
                    link_type = "ARP"
                if len(link_list) != 0:
                    for x in link_list:
                        y = x.split(" ")
                        link = {'source': str(y[0]),
                                'target': str(y[1]),
                                'cost': 1.0,
                                'properties': {
                                    'type': link_type
                                }}
                        links.append(link)
                    with open("scripts/nodes.json", "r+") as f:
                        file_data = json.load(f)
                        for link in links:
                            if link not in file_data["links"]:
                                file_data["links"].append(link)
                        f.seek(0)
                        json.dump(file_data, f, indent=4)
                        f.close()
                    copy2("scripts/nodes.json", "static/netjsongraph.js/data")
            except Exception:
                continue
    return return_nodes


def scan(target_ip, subnet, local):
    prep_json(target_ip)
    hosts = host_scan(subnet)
    initial_nodes = []
    executor = concurrent.futures.ProcessPoolExecutor(max_workers=10)
    futures = [executor.submit(full_scan, host) for host in hosts]
    concurrent.futures.wait(futures)
    for future in futures:
        initial_nodes.append(future.result())
    main_nodes = []
    for host in initial_nodes:
        main_node = main_node_creation(host)
        main_nodes.append(main_node)
    nodes_to_json(main_nodes)
    copy2("scripts/nodes.json", "static/netjsongraph.js/data")
    if local:
        continuous_packet_sniff(main_nodes)


if __name__ == '__main__':
    start_time = time.time()
    target_ip_address = sys.argv[1]
    scan_location = sys.argv[2]
    title = text2art("VulnViz")
    print("-------------------------------------------\n"
          + title +
          "-------------------------------------------\n")
    print("A Vulnerability Visualiser\nAuthor: Matthew Gill\n")
    subnet = target_ip_address + "/24"
    print(f"Current ip: {target_ip_address}")
    print(f"Current subnet: {subnet}\n")
    print("Scanning for hosts:")
    if scan_location == "remote":
        scan(target_ip_address, subnet, False)
    elif scan_location == "local":
        scan(target_ip_address, subnet, True)
        print(scan_location)
    else:
        print("invalid network parameter.")
        sys.exit(1)
    print(f"---{time.time() - start_time}--- Seconds")
    print("Running server . . .")
    cmd = "flask run"
    runServer = subprocess.Popen(cmd, shell=True)
    runServer.wait()
