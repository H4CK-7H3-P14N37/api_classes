import os
import re
import csv
import json
import random
import datetime
import xmltodict
import subprocess
from time import sleep
from tempfile import mkdtemp
from selenium import webdriver
import xml.etree.ElementTree as ET
from itertools import groupby, count
from random_user_agent.user_agent import UserAgent
from random_user_agent.params import SoftwareName, OperatingSystem, Popularity
from .voodoo import Voodoo


class PinCushionScan:
    def __init__(self, **kwargs):
        self.interface_name = "eth0"
        self.customer_name = "nocustomer"
        if os.environ.get("CUSTOMER"):
            self.customer_name = os.environ.get("CUSTOMER")
        elif kwargs.get("CUSTOMER"):
            self.customer_name = kwargs.get("CUSTOMER")
        self.base_dir = os.path.join(
            "/data/needlecraft/reports",
            self.customer_name)
        if os.environ.get("BASEDIR"):
            self.base_dir = os.environ.get("BASEDIR")
        elif kwargs.get("BASEDIR"):
            self.base_dir = kwargs.get("BASEDIR")
        self.masscan_bin = "/data/needlecraft/opt/masscan"
        if os.environ.get("MASSCANBIN"):
            self.masscan_bin = os.environ.get("MASSCANBIN")
        elif kwargs.get("MASSCANBIN"):
            self.masscan_bin = kwargs.get("MASSCANBIN")
        self.nmap_bin = "/data/needlecraft/opt/nmap/bin/nmap"
        if os.environ.get("NMAPBIN"):
            self.nmap_bin = os.environ.get("NMAPBIN")
        elif kwargs.get("NMAPBIN"):
            self.nmap_bin = kwargs.get("NMAPBIN")
        if not self.nmap_bin or not self.masscan_bin:
            raise Exception(
                "command not found: masscan and nmap not installed.")
        self.voodoo_obj = Voodoo(**kwargs)
        if not os.path.isdir(self.base_dir):
            os.makedirs(self.base_dir, exist_ok=True)
        # NOTE: anything below 4 will cause nmap to disable parrallelism and it will run one host at a time, 
        # which is not what we want. 4 is a good balance of speed and reliability for 
        # large scans, but feel free to adjust as needed.
        self.nmap_timing_num = 4
        self.dns_server = "1.1.1.1"

    def top_100_tcp_massscan(self, ip_list_filename):
        """masscan of the top 100 TCP ports"""
        output_filename = os.path.join(
            self.base_dir, f"{
                self.customer_name}_masscan_top100tcp_{
                datetime.datetime.now().isoformat()}.json")
        top_100_tcp_ports = (
            "7,9,13,21,22,23,25,26,37,53,79,80,81,88,106,110,111,113,119,135,"
            "139,143,144,179,199,389,427,443,444,445,465,513,514,515,543,544,"
            "548,554,587,631,646,873,990,993,995,1025,1026,1027,1028,1029,1030,"
            "1110,1433,1720,1723,1755,1900,2000,2001,2049,2121,2717,3000,3128,"
            "3306,3389,3986,4899,5000,5009,5051,5060,5101,5190,5357,5432,5631,"
            "5666,5800,5900,6000,6001,6646,7070,8000,8008,8009,8080,8081,8443,"
            "8888,9100,9999,10000,32768,49152,49153,49154,49155,49156")
        cmd_list = [
            self.masscan_bin,
            "--max-rate", "10000000",
            "--open",
            "--banners",
            "--ports", top_100_tcp_ports,
            "--source-port", "61000",
            "-e", self.interface_name,
            "-Pn",
            "--wait", "60",
            "-oJ", output_filename,
            "-iL", ip_list_filename,
            "--rate", "100000",
        ]
        completed_process_obj = subprocess.run(cmd_list)
        if completed_process_obj.returncode == 0:
            return output_filename
        return ''

    def initial_massscan(self, ip_list_filename):
        """masscan of stuff"""
        output_filename = os.path.join(
            self.base_dir, f"{
                self.customer_name}_masscan_{
                datetime.datetime.now().isoformat()}.json")
        output_pcap_filename = os.path.join(
            self.base_dir, f"{
                self.customer_name}_masscan_{
                datetime.datetime.now().isoformat()}.pcap")
        cmd_list = [
            self.masscan_bin,
            "--max-rate",
            "10000000",
            "--open",
            "--banners",
            "--ports",
            "0-65535",
            "--source-port",
            "61000",
            "-e",
            self.interface_name,
            "-Pn",
            "--wait",
            "60",
            "-oJ",
            output_filename,
            "-iL",
            ip_list_filename,
            "--rate",
            "100000",
            "--pcap",
            output_pcap_filename,
            "--tcp-mss",
        ]
        completed_process_obj = subprocess.run(cmd_list)
        if completed_process_obj.returncode == 0:
            return output_filename
        return ''

    def consolidate_port_range(self, port_list):
        def as_range(iterable):
            l = list(iterable)
            if len(l) > 1:
                return '{0}-{1}'.format(l[0], l[-1])
            else:
                return '{0}'.format(l[0])
        unique_port_list = list(set(port_list))
        return ','.join(
            as_range(g) for _,
            g in groupby(
                unique_port_list,
                key=lambda n,
                c=count(): int(n) -
                next(c)))

    def nmap_banner_cmd_from_masscan(self, masscan_json_filename):
        """
        Builds per-port nmap commands for TCP ports masscan did not fingerprint.
        Groups IPs by port so each nmap invocation targets only the IPs that
        need that specific port probed. Returns a list of (cmd_str, output_filename).
        """
        if os.path.getsize(masscan_json_filename) == 0:
            return []
        combined_dict = {}
        with open(masscan_json_filename, "r", encoding="utf-8") as f:
            masscan_data = json.load(f)
        for d in masscan_data:
            ip_addr = d.get('ip')
            ports = d.get('ports', [])
            if ip_addr not in combined_dict:
                combined_dict[ip_addr] = ports
            else:
                combined_dict[ip_addr].extend(ports)
        # First pass: collect every (ip, port) pair that has a banner in any
        # entry
        has_banner = set()
        for ip_addr, ports in combined_dict.items():
            for port in ports:
                service = port.get('service') or {}
                if service.get('banner', '').strip():
                    has_banner.add((ip_addr, port.get('port')))
        # Second pass: build port -> {ips} mapping for unfingerprinted pairs
        port_to_ips = {}
        for ip_addr, ports in combined_dict.items():
            for port in ports:
                port_num = port.get('port')
                if (ip_addr, port_num) not in has_banner:
                    port_to_ips.setdefault(port_num, set()).add(ip_addr)
        if not port_to_ips:
            return []
        cmd_list = []
        for port_num, ip_set in port_to_ips.items():
            ts = datetime.datetime.now().isoformat()
            ip_filename = os.path.join(
                self.base_dir,
                f"{self.customer_name}_nmap_iplist_{port_num}_{ts}.txt")
            nmap_output_filename = os.path.join(
                self.base_dir,
                f"{self.customer_name}_nmap_{port_num}_{ts}.xml")
            with open(ip_filename, "w", encoding="utf-8") as f:
                for ip_str in sorted(ip_set):
                    f.write(f"{ip_str}\n")
            cmd_list.append((
                f"{self.nmap_bin} -e {self.interface_name} -n --version-intensity 3 "
                f"--host-timeout 30s --max-retries 1 --min-hostgroup 64 --min-parallelism 64 "
                f"--max-parallelism 256 --min-rate 300 -Pn -T{self.nmap_timing_num} "
                f"--dns-servers {self.dns_server} -p{port_num} -oX {nmap_output_filename} "
                f"-iL {ip_filename}",
                nmap_output_filename
            ))
        return cmd_list

    def parse_masscan_tcp_json(self, masscan_json_filename, pdns_lookup=False):
        """Returns (port_data_list, http_port_list) for TCP ports masscan successfully fingerprinted."""
        port_data_list = []
        http_port_list = []
        if not masscan_json_filename or not os.path.isfile(
                masscan_json_filename):
            return port_data_list, http_port_list
        if os.path.getsize(masscan_json_filename) == 0:
            return port_data_list, http_port_list
        with open(masscan_json_filename, "r", encoding="utf-8") as f:
            masscan_data = json.load(f)
        combined_dict = {}
        for d in masscan_data:
            ip_addr = d.get('ip')
            ports = d.get('ports', [])
            if ip_addr not in combined_dict:
                combined_dict[ip_addr] = ports
            else:
                combined_dict[ip_addr].extend(ports)
        for ip_addr, ports in combined_dict.items():
            for port in ports:
                service = port.get('service') or {}
                banner = service.get('banner', '').strip()
                if not banner:
                    continue
                port_number = port.get('port')
                proto = port.get('proto', 'tcp')
                status = port.get('status', 'open')
                service_name = service.get('name', '')
                banner_clean = banner.replace('\n', ' ').strip()
                if port_number:
                    port_data_list.append(
                        f"{ip_addr}:{status}:{proto}:{port_number}:{banner_clean}")
                    if service_name in ('http', 'https'):
                        http_port_list.append(
                            f"http://{ip_addr}:{port_number}/")
                        http_port_list.append(
                            f"https://{ip_addr}:{port_number}/")
                        if pdns_lookup:
                            pdns_record_list = self.voodoo_obj.get_pdns_list(
                                ip_addr)
                            if pdns_record_list:
                                if len(pdns_record_list) > 30:
                                    pdns_record_list = pdns_record_list[:30]
                                for dns_name in pdns_record_list:
                                    http_port_list.append(
                                        f"http://{dns_name}:{port_number}/")
                                    http_port_list.append(
                                        f"https://{dns_name}:{port_number}/")
        return port_data_list, http_port_list

    def run_nmap_command(self, cmd_str, output_filename):
        """run name command"""
        cmd_list = cmd_str.split()
        completed_process_obj = subprocess.run(cmd_list)
        if completed_process_obj.returncode == 0:
            return output_filename
        return ''

    def scan_top_100_udp_ports(self, ip_list_filename):
        """UDP scan of the top 100 UDP ports using masscan"""
        output_filename = os.path.join(
            self.base_dir, f"{
                self.customer_name}_masscan_udp_{
                datetime.datetime.now().isoformat()}.json")
        top_100_udp_ports = [
            "7", "9", "17", "19", "49", "53", "67", "68", "69", "80", "88", "111", "120", "123",
            "135", "136", "137", "138", "139", "158", "161", "162", "177", "427", "443", "445",
            "497", "500", "514", "515", "518", "520", "593", "623", "626", "631", "996", "997",
            "998", "999", "1022", "1023", "1025", "1026", "1027", "1028", "1029", "1030",
            "1433", "1434", "1645", "1646", "1701", "1718", "1719", "1812", "1813", "1900",
            "2000", "2048", "2049", "2222", "2223", "3283", "3456", "3703", "4444", "4500",
            "5000", "5060", "5353", "5632", "6329", "7938", "9200", "10000", "17185", "20031",
            "23945", "26000", "27015", "32768", "32769", "32815", "33281", "33354", "34555",
            "35500", "37444", "39213", "41524", "49193", "49194", "49200", "50040", "50300",
            "52736", "54281", "65024",
        ]
        udp_port_str = ",".join(f"U:{p}" for p in top_100_udp_ports)
        cmd_list = [
            self.masscan_bin,
            "--max-rate", "10000",
            "--open",
            "--banners",
            "--ports", udp_port_str,
            "-e", self.interface_name,
            "--wait", "10",
            "-oJ", output_filename,
            "-iL", ip_list_filename,
        ]
        completed_process_obj = subprocess.run(cmd_list)
        if completed_process_obj.returncode == 0:
            return output_filename
        return ''

    def parse_masscan_udp_json(self, masscan_json_filename):
        """Returns port_data_list for UDP ports masscan successfully fingerprinted (has banner)."""
        port_data_list = []
        if not masscan_json_filename or not os.path.isfile(
                masscan_json_filename):
            return port_data_list
        if os.path.getsize(masscan_json_filename) == 0:
            return port_data_list
        with open(masscan_json_filename, "r", encoding="utf-8") as f:
            masscan_data = json.load(f)
        combined_dict = {}
        for d in masscan_data:
            ip_addr = d.get('ip')
            ports = d.get('ports', [])
            if ip_addr not in combined_dict:
                combined_dict[ip_addr] = ports
            else:
                combined_dict[ip_addr].extend(ports)
        for ip_addr, ports in combined_dict.items():
            for port in ports:
                service = port.get('service') or {}
                banner = service.get('banner', '').strip()
                if not banner:
                    continue
                port_number = port.get('port')
                proto = port.get('proto', 'udp')
                status = port.get('status', 'open')
                banner_clean = banner.replace('\n', ' ').strip()
                if ip_addr and port_number:
                    port_data_list.append(
                        f"{ip_addr}:{status}:{proto}:{port_number}:{banner_clean}")
        return port_data_list

    def nmap_udp_banner_cmd_from_masscan(self, masscan_udp_json_filename):
        """
        Builds per-port nmap UDP commands for ports masscan did not fingerprint.
        Groups IPs by port so each nmap invocation targets only the IPs that
        need that specific port probed. Returns a list of (cmd_str, output_filename).
        """
        if not masscan_udp_json_filename or not os.path.isfile(
                masscan_udp_json_filename):
            return []
        if os.path.getsize(masscan_udp_json_filename) == 0:
            return []
        combined_dict = {}
        with open(masscan_udp_json_filename, "r", encoding="utf-8") as f:
            masscan_data = json.load(f)
        for d in masscan_data:
            ip_addr = d.get('ip')
            ports = d.get('ports', [])
            if ip_addr not in combined_dict:
                combined_dict[ip_addr] = ports
            else:
                combined_dict[ip_addr].extend(ports)
        # First pass: collect every (ip, port) pair that has a banner in any
        # entry
        has_banner = set()
        for ip_addr, ports in combined_dict.items():
            for port in ports:
                service = port.get('service') or {}
                if service.get('banner', '').strip():
                    has_banner.add((ip_addr, port.get('port')))
        # Second pass: build port -> {ips} mapping for unfingerprinted pairs
        port_to_ips = {}
        for ip_addr, ports in combined_dict.items():
            for port in ports:
                port_num = port.get('port')
                if (ip_addr, port_num) not in has_banner:
                    port_to_ips.setdefault(port_num, set()).add(ip_addr)
        if not port_to_ips:
            return []
        cmd_list = []
        for port_num, ip_set in port_to_ips.items():
            ts = datetime.datetime.now().isoformat()
            ip_filename = os.path.join(
                self.base_dir,
                f"{self.customer_name}_nmap_udp_iplist_{port_num}_{ts}.txt")
            nmap_output_filename = os.path.join(
                self.base_dir,
                f"{self.customer_name}_nmap_udp_{port_num}_{ts}.xml")
            with open(ip_filename, "w", encoding="utf-8") as f:
                for ip_str in sorted(ip_set):
                    f.write(f"{ip_str}\n")
            cmd_list.append((
                f"{self.nmap_bin} -e {self.interface_name} -n -sU --version-intensity 3 --host-timeout 30s "
                f"--max-retries 1 --min-hostgroup 64 --min-parallelism 64 --max-parallelism 256 --min-rate 300 -Pn "
                f"-T{self.nmap_timing_num} --dns-servers {self.dns_server} --script=banner -p{port_num} "
                f"-oX {nmap_output_filename} -iL {ip_filename}",
                nmap_output_filename
            ))
        return cmd_list

    def parse_nmap_xml(self, nmap_results_xml_filename, pdns_lookup=False):
        """
            this parses nmap xml and gives a list
            of open ports with banners and a list of
            urls to screenshot that come back as HTTP/HTTPs
        """
        with open(nmap_results_xml_filename, 'r') as f:
            xml_data = f.read().strip()
            json_data = xmltodict.parse(xml_data)
        http_port_list = []
        port_data_list = []
        host_list = json_data.get('nmaprun').get('host')
        if host_list:
            if isinstance(host_list, dict):
                host_list = [host_list]
            for host in host_list:
                if host.get('status').get('@state') == 'up':
                    ip_addrs = host.get('address')
                    if isinstance(ip_addrs, dict):
                        ip_addrs = [ip_addrs]
                    for ip_addr_dict in ip_addrs:
                        # exclude mac's
                        if ip_addr_dict.get('@addrtype') == 'mac':
                            continue
                        ip_addr = ip_addr_dict.get('@addr')
                        port_status_list = []
                        ports = host.get('ports')
                        if ports:
                            ports = ports.get('port')
                            if ports:
                                if isinstance(ports, dict):
                                    ports = [ports]
                                for port in ports:
                                    if isinstance(port, dict):
                                        banner = ''
                                        port_number = ''
                                        service_name = ''
                                        port_protocol = ''
                                        status = port.get('state')
                                        if status:
                                            status = status.get('@state')
                                        if status == 'open':
                                            port_number = port.get('@portid')
                                            port_protocol = port.get(
                                                '@protocol')
                                        if status == 'closed':
                                            port_number = port.get('@portid')
                                            port_protocol = port.get(
                                                '@protocol')
                                        script = port.get('script')
                                        if isinstance(script, dict):
                                            if script.get('@id') == "banner":
                                                banner = script.get('@output')
                                        if isinstance(script, list):
                                            script_list = script
                                            for script in script_list:
                                                if script.get(
                                                        '@id') == "banner":
                                                    banner = script.get(
                                                        '@output')
                                        service = port.get('service')
                                        if service:
                                            name = service.get('@name', '')
                                            product = service.get(
                                                '@product', '')
                                            extra_info = service.get(
                                                '@extrainfo', '')
                                            service_name = f"{name} {product} {extra_info}".replace(
                                                ":", " ")
                                            if name in [
                                                    "http", "https"] and port_number and port_protocol:
                                                http_port_list.append(
                                                    f"http://{ip_addr}:{port_number}/")
                                                http_port_list.append(
                                                    f"https://{ip_addr}:{port_number}/")
                                                if pdns_lookup:
                                                    pdns_record_list = self.voodoo_obj.get_pdns_list(
                                                        ip_addr)
                                                    if pdns_record_list:
                                                        # if the list is longer than 30,
                                                        # we cap it to the
                                                        # first 30. Why 30? Why
                                                        # not...
                                                        if len(
                                                                pdns_record_list) > 30:
                                                            pdns_record_list = pdns_record_list[:30]
                                                        for dns_name in pdns_record_list:
                                                            http_port_list.append(
                                                                f"http://{dns_name}:{port_number}/")
                                                            http_port_list.append(
                                                                f"https://{dns_name}:{port_number}/")
                                        if banner and port_number:
                                            banner = banner.replace(
                                                "\n", " ").strip()
                                            port_status_list.append(
                                                f"{status}:{port_protocol}:{port_number}:{banner}")
                                        elif port_number and service_name:
                                            port_status_list.append(
                                                f"{status}:{port_protocol}:{port_number}:{service_name}")
                                        elif port_number:
                                            port_status_list.append(
                                                f"{status}:{port_protocol}:{port_number}:")
                        if port_status_list:
                            for port_status in port_status_list:
                                port_data_list.append(
                                    f"{ip_addr}:{port_status}")
        return port_data_list, http_port_list

    def seance(
            self,
            cidr_list,
            udp_scan=False,
            pdns_lookup=False,
            top_tcp=False,
            skip_nmap=False):
        """to do the full scan to find all open ports, we do this."""
        if not os.path.isfile(cidr_list):
            raise Exception(f"{cidr_list} file doesn't exist.")
        if top_tcp:
            masscan_output_json_filename = self.top_100_tcp_massscan(cidr_list)
        else:
            masscan_output_json_filename = self.initial_massscan(cidr_list)
        if not masscan_output_json_filename or not os.path.isfile(
                masscan_output_json_filename):
            raise Exception(
                f"{masscan_output_json_filename} file doesn't exist.")
        return_port_list = []
        return_http_list = []
        # TCP: include ports masscan already fingerprinted
        masscan_tcp_port_list, masscan_tcp_http_list = self.parse_masscan_tcp_json(
            masscan_output_json_filename, pdns_lookup)
        if masscan_tcp_port_list:
            return_port_list.extend(masscan_tcp_port_list)
        if masscan_tcp_http_list:
            return_http_list.extend(masscan_tcp_http_list)
        # TCP: run nmap only on ports masscan did not fingerprint, one port at
        # a time
        if not skip_nmap:
            for nmap_cmd, nmap_output in self.nmap_banner_cmd_from_masscan(
                    masscan_output_json_filename):
                nmap_results_xml_file = self.run_nmap_command(
                    nmap_cmd, nmap_output)
                if nmap_results_xml_file:
                    tcp_port_data_list, tcp_http_port_list = self.parse_nmap_xml(
                        nmap_results_xml_file, pdns_lookup)
                    if tcp_port_data_list:
                        return_port_list.extend(tcp_port_data_list)
                    if tcp_http_port_list:
                        return_http_list.extend(tcp_http_port_list)
        if udp_scan:
            masscan_udp_json_file = self.scan_top_100_udp_ports(cidr_list)
            if not masscan_udp_json_file:
                raise Exception("masscan udp scan failed.")
            # UDP: include ports masscan already fingerprinted
            udp_masscan_port_list = self.parse_masscan_udp_json(
                masscan_udp_json_file)
            if udp_masscan_port_list:
                return_port_list.extend(udp_masscan_port_list)
            # UDP: run nmap only on ports masscan did not fingerprint, one port
            # at a time
            if not skip_nmap:
                for nmap_udp_cmd, nmap_udp_output in self.nmap_udp_banner_cmd_from_masscan(
                        masscan_udp_json_file):
                    nmap_udp_xml_file = self.run_nmap_command(
                        nmap_udp_cmd, nmap_udp_output)
                    if nmap_udp_xml_file:
                        udp_nmap_port_list, _ = self.parse_nmap_xml(
                            nmap_udp_xml_file, pdns_lookup)
                        if udp_nmap_port_list:
                            return_port_list.extend(udp_nmap_port_list)
        if return_port_list:
            return_port_list = list(set(return_port_list))
        if return_http_list:
            return_http_list = list(set(return_http_list))
        return return_port_list, return_http_list

    def save_report(
            self,
            cidr_list,
            udp_scan=False,
            pdns_lookup=False,
            top_tcp=False,
            skip_nmap=False):
        return_port_list, return_http_list = self.seance(
            cidr_list, udp_scan, pdns_lookup, top_tcp, skip_nmap)
        csv_columns = [
            "ip_addr",
            "status",
            "protocol",
            "port",
            "service-banner"]
        attack_surface_output_ports_filename = os.path.join(
            self.base_dir, f"{
                self.customer_name}_attack_surface_ports_{
                datetime.datetime.now().isoformat()}.csv")
        attack_surface_output_url_filename = os.path.join(
            self.base_dir, f"{
                self.customer_name}_attack_surface_urls_{
                datetime.datetime.now().isoformat()}.csv")
        if return_port_list:
            with open(attack_surface_output_ports_filename, 'w', newline='\n', encoding="utf-8") as csvfile:
                csv_writer = csv.writer(csvfile)
                csv_writer.writerow(csv_columns)
                for port_row in return_port_list:
                    csv_writer.writerow(port_row.split(":"))
        if return_http_list:
            with open(attack_surface_output_url_filename, 'w', newline='\n', encoding="utf-8") as urlfile:
                for url in return_http_list:
                    urlfile.write(f"{url}\n")
        if return_port_list and return_http_list:
            return (
                attack_surface_output_ports_filename,
                attack_surface_output_url_filename,
                return_port_list,
                return_http_list
            )
        elif return_port_list:
            return (
                attack_surface_output_ports_filename,
                None,
                return_port_list,
                return_http_list
            )
        return (
            None,
            None,
            return_port_list,
            return_http_list
        )

    def run_rtsp_brute_force(self, ip_list):
        "brute force rtsp urls"
        nmap_output_filename = os.path.join(
            self.base_dir, f"{
                self.customer_name}_nmap_rtsp_{
                datetime.datetime.now().isoformat()}.xml")
        nmap_input_filename = os.path.join(
            self.base_dir, f"{
                self.customer_name}_rtsp_nmap_ip_list_{
                datetime.datetime.now().isoformat()}.txt")
        with open(nmap_input_filename, 'w') as f:
            f.write("\n".join(ip_list))
        nmap_cmd_str = f"{
            self.nmap_bin} -e {
            self.interface_name} -p554 --script=rtsp-url-brute -T5 -oX {nmap_output_filename} -iL {nmap_input_filename}"
        nmap_rtsp_xml_file = self.run_nmap_command(
            nmap_cmd_str, nmap_output_filename)
        return nmap_rtsp_xml_file

    def parse_nmap_output_for_rtsp_urls(self, nmap_xml_output):
        output_list = []
        tree = ET.parse(nmap_xml_output)
        root = tree.getroot()
        for child in root:
            if child.tag == "host":
                for cc in child:
                    if cc.tag == "ports":
                        for port in cc:
                            for pelm in port:
                                if pelm.tag == "script":
                                    for scriptelm in pelm:
                                        if scriptelm.tag == "table" and scriptelm.attrib.get(
                                                'key') == "discovered":
                                            for elm in scriptelm:
                                                output_list.append(elm.text)
        return output_list


class PinCushionHTTP:
    def __init__(self, **kwargs):
        self.customer_name = "nocustomer"
        if os.environ.get("CUSTOMER"):
            self.customer_name = os.environ.get("CUSTOMER")
        elif kwargs.get("CUSTOMER"):
            self.customer_name = kwargs.get("CUSTOMER")
        self.base_dir = os.path.join(
            "/data/needlecraft/reports",
            self.customer_name)
        if os.environ.get("BASEDIR"):
            self.base_dir = os.environ.get("BASEDIR")
        elif kwargs.get("BASEDIR"):
            self.base_dir = kwargs.get("BASEDIR")
        self.chrome_binary = "/data/needlecraft/opt/chrome-linux64/chrome"
        self.chrome_driver = "/data/needlecraft/opt/chromedriver-linux64/chromedriver"
        if os.environ.get("CHROMEDRIVER"):
            self.chrome_driver = os.environ.get("CHROMEDRIVER")
        elif kwargs.get("CHROMEDRIVER"):
            self.chrome_driver = kwargs.get("CHROMEDRIVER")
        if os.environ.get("CHROMEBIN"):
            self.chrome_binary = os.environ.get("CHROMEBIN")
        elif kwargs.get("CHROMEBIN"):
            self.chrome_binary = kwargs.get("CHROMEBIN")
        if not os.path.isdir(self.base_dir):
            os.makedirs(self.base_dir, exist_ok=True)
        self.proxy_server = "127.0.0.1:9050"

    def get_screenshot(self, http_url):
        """screenshot URLs and save as PNG"""
        software_names = [
            SoftwareName.CHROME.value,
            SoftwareName.FIREFOX.value,
            SoftwareName.EDGE.value
        ]
        user_agent_rotator_windows = UserAgent(
            software_names=software_names,
            operating_systems=[
                OperatingSystem.WINDOWS.value
            ],
            popularity=[
                Popularity.POPULAR.value
            ],
            limit=18
        )
        user_agent_rotator_mac = UserAgent(
            software_names=software_names,
            operating_systems=[
                OperatingSystem.MAC.value
            ],
            popularity=[
                Popularity.POPULAR.value
            ],
            limit=18
        )
        # Get list of user agents.
        user_agents_windows = user_agent_rotator_windows.get_user_agents()
        user_agents_mac = user_agent_rotator_mac.get_user_agents()
        all_user_agents = [u.get("user_agent") for u in user_agents_windows]
        all_user_agents.extend([u.get("user_agent") for u in user_agents_mac])
        # Get Random User Agent String.
        user_agent = random.choice(all_user_agents)
        options = webdriver.ChromeOptions()
        options.binary_location = self.chrome_binary
        # https://peter.sh/experiments/chromium-command-line-switches/
        # https://github.com/GoogleChrome/chrome-launcher/blob/main/docs/chrome-flags-for-tools.md
        options.add_argument('--headless=new')
        options.add_argument('--no-sandbox')
        options.add_argument("--disable-gpu")
        options.add_argument('--window-size=1280,1696')
        options.add_argument("--single-process")
        options.add_argument("--disable-web-security")
        options.add_argument("--use-fake-ui-for-media-stream")
        options.add_argument("--enable-chrome-browser-cloud-management")
        options.add_argument("--remote-allow-origins=*")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--disable-dev-tools")
        options.add_argument("--no-zygote")
        options.add_argument(f"--user-data-dir={mkdtemp()}")
        options.add_argument(f"--data-path={mkdtemp()}")
        options.add_argument(f"--disk-cache-dir={mkdtemp()}")
        options.add_argument("--remote-debugging-port=9222")
        options.add_argument('--ignore-certificate-errors')
        options.add_argument('--allow-insecure-localhost')
        options.add_argument('--ignore-ssl-errors')
        options.add_argument('--ignore-certificate-errors-spki-list')
        options.add_argument('--ssl-version-min=ssl2')
        options.add_argument('--hide-scrollbars')
        options.add_argument('--no-cache')
        options.add_argument('--disable-extensions')
        options.add_argument(f'--user-agent={user_agent}')
        options.add_argument('--disable-client-side-phishing-detection')
        if ".onion" in http_url.lower():
            options.add_argument(
                f'--proxy-server=socks5://{self.proxy_server}')
        service = webdriver.chrome.service.Service(
            executable_path=self.chrome_driver)
        driver = webdriver.Chrome(
            service=service,
            options=options
        )
        driver.set_page_load_timeout(30)
        driver.get(http_url)
        sleep(10)
        image = driver.get_screenshot_as_png()
        # Saving this if I ever see a need for source code
        # page_source = driver.page_source
        # escape(page_source)
        driver.quit()
        filename = re.sub('[^A-Za-z0-9]+', '_', http_url)
        url_filename = "{}.png".format(filename)
        random_filename = os.path.join(self.base_dir, url_filename)
        with open(random_filename, "wb") as f:
            f.write(image)
        return random_filename

    def run_screenshot_list(self, url_list):
        """run a list of URLs"""
        hit_urls_list = []
        for url in url_list:
            try:
                response = self.get_screenshot(url)
                if response:
                    hit_urls_list.append(response)
            except Exception as e:
                print(e)
                pass
        return hit_urls_list


class PinCushionRTSP:
    def __init__(self, **kwargs):
        self.customer_name = "nocustomer"
        if os.environ.get("CUSTOMER"):
            self.customer_name = os.environ.get("CUSTOMER")
        elif kwargs.get("CUSTOMER"):
            self.customer_name = kwargs.get("CUSTOMER")
        self.base_dir = os.path.join(
            "/data/needlecraft/reports",
            self.customer_name)
        if os.environ.get("BASEDIR"):
            self.base_dir = os.environ.get("BASEDIR")
        elif kwargs.get("BASEDIR"):
            self.base_dir = kwargs.get("BASEDIR")
        if not os.path.isdir(self.base_dir):
            os.makedirs(self.base_dir, exist_ok=True)
        self.FFMPEG_BIN = "/usr/bin/ffmpeg"

    def get_rtsp_tcp_screenshot(self, rtsp_url):
        output_filepath = os.path.join(
            self.base_dir, f"{
                rtsp_url.replace(
                    '/', '_')}.jpg")
        cmd_list = f"{
            self.FFMPEG_BIN} -y -i {rtsp_url} -f mpegts -frames:v 2 {output_filepath}".split()
        completed_process_obj = subprocess.run(cmd_list)
        if completed_process_obj.returncode == 0:
            return output_filepath
        return ''

    def get_rtsp_udp_screenshot(self, rtsp_url):
        output_filepath = os.path.join(
            self.base_dir, f"{
                rtsp_url.replace(
                    '/', '_')}.jpg")
        cmd_list = f"{
            self.FFMPEG_BIN} -y -i {rtsp_url} -frames:v 2 {output_filepath}".split()
        completed_process_obj = subprocess.run(cmd_list)
        if completed_process_obj.returncode == 0:
            return output_filepath
        return ''


class PinCushionSSLSCAN:
    def __init__(self, **kwargs):
        self.customer_name = "nocustomer"
        if os.environ.get("CUSTOMER"):
            self.customer_name = os.environ.get("CUSTOMER")
        elif kwargs.get("CUSTOMER"):
            self.customer_name = kwargs.get("CUSTOMER")
        self.base_dir = os.path.join(
            "/data/needlecraft/reports",
            self.customer_name)
        if os.environ.get("BASEDIR"):
            self.base_dir = os.environ.get("BASEDIR")
        elif kwargs.get("BASEDIR"):
            self.base_dir = kwargs.get("BASEDIR")
        if not os.path.isdir(self.base_dir):
            os.makedirs(self.base_dir, exist_ok=True)
        self.sslscan_bin = "/usr/bin/sslscan"

    def run_sslscan(self, domain):
        filename = re.sub('[^A-Za-z0-9]+', '_', domain)
        url_filename = f"{filename}.xml"
        random_filename = os.path.join(self.base_dir, url_filename)
        cmd_list = f"{
            self.sslscan_bin} --xml={random_filename} {domain}".split()
        completed_process_obj = subprocess.run(cmd_list)
        if completed_process_obj.returncode == 0:
            return random_filename
        return ''

    def convert_xml_to_json(self, input_file):
        try:
            with open(input_file, 'r') as f:
                xml_data = f.read().strip()
                json_data = xmltodict.parse(xml_data)
                return json_data
        except Exception as e:
            print(e)
            return {}

    def get_sslscan_results(self, domain):
        return_filename = self.run_sslscan(domain)
        if return_filename:
            return self.convert_xml_to_json(return_filename)
        return {}

    def audit_scan_results(self, domain):
        results = self.get_sslscan_results(domain)
        if results:
            return self.parse_sslscan_xml(domain, results)
        return [], []

    def parse_sslscan_xml(self, domain, results):
        cert_problems_list = []
        cert_problems_dict = {}
        bad_ciphers_list = []
        if results:
            ssl_test_results = results.get('document', {}).get('ssltest', {})
            if ssl_test_results:
                cipher_list = ssl_test_results.get('cipher')
                if cipher_list:
                    bad_ciphers_list = [
                        d for d in cipher_list if isinstance(
                            d, dict) and (
                            d.get('@strength') != "strong" and d.get('@strength') != "acceptable") or (
                            d.get("@sslversion") != "TLSv1.2" and d.get("@sslversion") != "TLSv1.3")]
                    if bad_ciphers_list:
                        bad_ciphers_list = [
                            f"{domain}:{d.get('@sslversion')}:{d.get('@cipher')}" for d in bad_ciphers_list]
                cert_dict = ssl_test_results.get('certificates')
                if cert_dict:
                    cert_dict = cert_dict.get('certificate')
                    algo = cert_dict.get('signature-algorithm')
                    if algo != "sha256WithRSAEncryption" and algo != "ecdsa-with-SHA384":
                        cert_problems_dict.update(
                            {'signature-algorithm': algo})
                    self_signed = cert_dict.get('self-signed')
                    if self_signed == 'true':
                        cert_problems_dict.update({'self-signed': self_signed})
                    expired = cert_dict.get('expired')
                    if expired == 'true':
                        cert_problems_dict.update({'expired': expired})
                    # TODO: later tackle the issue with CA issues not being
                    # trusted
        if cert_problems_dict:
            for k, v in cert_problems_dict.items():
                cert_problems_list.append(f"{domain}:{k}:{v}")
        return bad_ciphers_list, cert_problems_list

    def run_sslscan_list(self, domain_list):
        cert_problems_list = []
        bad_ciphers_list = []
        for domain in domain_list:
            cipher_list, cert_list = self.audit_scan_results(domain)
            if cipher_list:
                bad_ciphers_list.extend(cipher_list)
            if cert_list:
                cert_problems_list.extend(cert_list)
        attack_surface_output_certs_filename = os.path.join(
            self.base_dir, f"{
                self.customer_name}_attack_surface_certs_{
                datetime.datetime.now().isoformat()}.csv")
        attack_surface_output_ciphers_filename = os.path.join(
            self.base_dir, f"{
                self.customer_name}_attack_surface_ciphers_{
                datetime.datetime.now().isoformat()}.csv")
        if cert_problems_list:
            with open(attack_surface_output_certs_filename, 'w', newline='\n', encoding="utf-8") as csvfile:
                csv_writer = csv.writer(csvfile)
                csv_columns = ["domain", "cert_property", "value"]
                csv_writer.writerow(csv_columns)
                for cert_row in cert_problems_list:
                    csv_writer.writerow(cert_row.split(":"))
        if bad_ciphers_list:
            with open(attack_surface_output_ciphers_filename, 'w', newline='\n', encoding="utf-8") as urlfile:
                csv_writer = csv.writer(urlfile)
                csv_columns = ["domain", "protocol", "cipher"]
                csv_writer.writerow(csv_columns)
                for cipher_row in bad_ciphers_list:
                    csv_writer.writerow(cipher_row.split(":"))
        return bad_ciphers_list, cert_problems_list, attack_surface_output_ciphers_filename, attack_surface_output_certs_filename


class PinCushionInternetDB:
    def __init__(self, **kwargs):
        self.customer_name = "nocustomer"
        if os.environ.get("CUSTOMER"):
            self.customer_name = os.environ.get("CUSTOMER")
        elif kwargs.get("CUSTOMER"):
            self.customer_name = kwargs.get("CUSTOMER")
        self.base_dir = os.path.join(
            "/data/needlecraft/reports",
            self.customer_name)
        if os.environ.get("BASEDIR"):
            self.base_dir = os.environ.get("BASEDIR")
        elif kwargs.get("BASEDIR"):
            self.base_dir = kwargs.get("BASEDIR")
        self.voodoo_obj = Voodoo(**kwargs)
        if not os.path.isdir(self.base_dir):
            os.makedirs(self.base_dir, exist_ok=True)

    def internetdb_report_table(self, output):
        table_data = ""
        if output:
            for idb_dict in output:
                for k, v in idb_dict.items():
                    if isinstance(v, list):
                        tmp_values_list = list(map(str, v))
                        table_data += "{}: {}\n".format(k,
                                                        "\n       ".join(tmp_values_list))
                    else:
                        table_data += "{}: {}\n".format(k, v)
                    if k == "vulns":
                        table_data += "\n"
        return self.voodoo_obj.generate_ascii_table("InternetDB", table_data)

    def mass_internetdb_lookup(self, ip_list):
        return_list = []
        internetdb_filename = None
        internetdb_table = ""
        ip_list = self.voodoo_obj.expand_cidr_list(ip_list)
        for ip_addr in ip_list:
            results_dict = self.voodoo_obj.get_internetdb_result(ip_addr)
            if results_dict:
                return_list.append(results_dict)
            sleep(1)
        if return_list:
            internetdb_filename = os.path.join(
                self.base_dir, f"{
                    self.customer_name}_internetdb_{
                    datetime.datetime.now().isoformat()}.json")
            with open(internetdb_filename, "w") as f:
                f.write(json.dumps(return_list))
            internetdb_table = self.internetdb_report_table(return_list)
        return return_list, internetdb_filename, internetdb_table


class PinCushionRecon:
    def __init__(self, **kwargs):
        self.customer_name = "nocustomer"
        if os.environ.get("CUSTOMER"):
            self.customer_name = os.environ.get("CUSTOMER")
        elif kwargs.get("CUSTOMER"):
            self.customer_name = kwargs.get("CUSTOMER")
        self.base_dir = os.path.join(
            "/data/needlecraft/reports",
            self.customer_name)
        if os.environ.get("BASEDIR"):
            self.base_dir = os.environ.get("BASEDIR")
        elif kwargs.get("BASEDIR"):
            self.base_dir = kwargs.get("BASEDIR")
        self.RECON_BIN = "/usr/bin/recon-ng"
        if not os.path.isdir(self.base_dir):
            os.makedirs(self.base_dir, exist_ok=True)

    def run_recon(self, domain):
        output_recon_json_filename = os.path.join(
            self.base_dir, f"{self.customer_name}_{domain}.json")
        recon_resource_filename = os.path.join(
            self.base_dir, f"{self.customer_name}_{domain}.rc")
        with open(recon_resource_filename, "w") as f:
            f.write(f"""workspaces remove {domain}
workspaces create {domain}
workspaces load {domain}
marketplace install reporting/json
marketplace install recon/domains-contacts/whois_pocs
modules load recon/domains-contacts/whois_pocs
options set SOURCE {domain}
run
modules load reporting/json
options set FILENAME {output_recon_json_filename}
run
exit
            """)
        exit_code = subprocess.check_call(
            f"{self.RECON_BIN} -r {recon_resource_filename}",
            shell=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.STDOUT
        )
        if exit_code == 0:
            return output_recon_json_filename
        return

    def whois_poc_report_table(self, output):
        table_data = ""
        if output:
            contacts = output.get("contacts")
            if contacts:
                for recon_dict in contacts:
                    for k, v in recon_dict.items():
                        if k == "module":
                            table_data += "\n"
                            continue
                        if v:
                            table_data += "{}: {}\n".format(k, v)
        return table_data

    def whois_poc_lookup(self, domain_name):
        return_list = []
        whois_poc_filename = None
        whois_poc_table = ""
        recon_filename = self.run_recon(domain_name)
        if recon_filename:
            with open(recon_filename, "r") as f:
                return_list = json.load(f)
            whois_poc_table = self.whois_poc_report_table(return_list)
            whois_poc_filename = recon_filename
        return return_list, whois_poc_filename, whois_poc_table


class PinCushionDehashed:
    def __init__(self, **kwargs):
        self.customer_name = "nocustomer"
        if os.environ.get("CUSTOMER"):
            self.customer_name = os.environ.get("CUSTOMER")
        elif kwargs.get("CUSTOMER"):
            self.customer_name = kwargs.get("CUSTOMER")
        self.base_dir = os.path.join(
            "/data/needlecraft/reports",
            self.customer_name)
        if os.environ.get("BASEDIR"):
            self.base_dir = os.environ.get("BASEDIR")
        elif kwargs.get("BASEDIR"):
            self.base_dir = kwargs.get("BASEDIR")
        if not os.path.isdir(self.base_dir):
            os.makedirs(self.base_dir, exist_ok=True)
