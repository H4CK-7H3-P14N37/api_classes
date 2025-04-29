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
        self.nmap_timing_num = 1
        self.dns_server = "1.1.1.1"

    def initial_massscan(self, ip_list_filename):
        """masscan of stuff"""
        output_filename = os.path.join(
            self.base_dir,
            f"{self.customer_name}_masscan_{datetime.datetime.now().isoformat()}.json")
        output_pcap_filename = os.path.join(
            self.base_dir,
            f"{self.customer_name}_masscan_{datetime.datetime.now().isoformat()}.pcap")
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
        converts a masscan output to an nmap scan for
        better banner grabbing
        """
        combined_dict = {}
        nmap_output_filename = os.path.join(
            self.base_dir,
            f"{self.customer_name}_nmap_{datetime.datetime.now().isoformat()}.xml")
        if os.path.getsize(masscan_json_filename) > 0:
            with open(masscan_json_filename, "r", encoding="utf-8") as f:
                masscan_data = json.load(f)
            for d in masscan_data:
                ip_addr = d.get('ip')
                ports = d.get('ports')
                if ip_addr not in combined_dict.keys():
                    combined_dict.update({ip_addr: ports})
                else:
                    combined_dict[ip_addr].extend(ports)
            full_ip_list = []
            full_port_list = []
            for ip_addr, ports in combined_dict.items():
                full_ip_list.append(ip_addr)
                for port in ports:
                    full_port_list.append(port.get('port'))
            ip_filename = os.path.join(
                self.base_dir,
                f"{self.customer_name}_nmap_iplist_{datetime.datetime.now().isoformat()}.txt")
            with open(ip_filename, "w", encoding="utf-8") as f:
                for ip_str in full_ip_list:
                    f.write(f"{ip_str}\n")
            # Possible problem here
            # if nmap string gets too long because of the port list
            port_str = self.consolidate_port_range(full_port_list)
            return (
                f"{self.nmap_bin} -e {self.interface_name} -n -sV -Pn -O -T{self.nmap_timing_num} --dns-servers {self.dns_server} --script=banner -p{port_str} -oX {nmap_output_filename} -iL {ip_filename}",
                nmap_output_filename)
        return (None, None)

    def run_nmap_command(self, cmd_str, output_filename):
        """run name command"""
        cmd_list = cmd_str.split()
        completed_process_obj = subprocess.run(cmd_list)
        if completed_process_obj.returncode == 0:
            return output_filename
        return ''

    def initial_nmapscan(self, ip_list_filename):
        """setup a tcp nmap scan"""
        nmap_output_filename = os.path.join(
            self.base_dir,
            f"{self.customer_name}_nmap_{datetime.datetime.now().isoformat()}.xml")
        nmap_cmd_str = f"{self.nmap_bin} -e {self.interface_name} -n --max-rtt-timeout 1s --min-parallelism 100 -sT -sV -O --script=banner -Pn -T{self.nmap_timing_num} -oX {nmap_output_filename} -iL {ip_list_filename}"
        nmap_udp_xml_file = self.run_nmap_command(
            nmap_cmd_str, nmap_output_filename)
        return nmap_udp_xml_file

    def scan_top_100_udp_ports(self, ip_list_filename):
        """setup a udp nmap scan"""
        nmap_output_filename = os.path.join(
            self.base_dir,
            f"{self.customer_name}_nmap_{datetime.datetime.now().isoformat()}.xml")
        nmap_cmd_str = f"{self.nmap_bin} -e {self.interface_name} -n --max-rtt-timeout 1s --min-parallelism 100 -sU -sV -O --script=banner -Pn -T{self.nmap_timing_num} -F -oX {nmap_output_filename} -iL {ip_list_filename}"
        nmap_udp_xml_file = self.run_nmap_command(
            nmap_cmd_str, nmap_output_filename)
        return nmap_udp_xml_file

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

    def seance(self, cidr_list, udp_scan=False, pdns_lookup=False):
        """to do the full scan to find all open ports, we do this."""
        if not os.path.isfile(cidr_list):
            raise Exception(f"{cidr_list} file doesn't exist.")
        masscan_output_json_filename = self.initial_massscan(cidr_list)
        if not masscan_output_json_filename and not os.path.isfile(
                masscan_output_json_filename):
            raise Exception(
                f"{masscan_output_json_filename} file doesn't exist.")
        nmap_results_xml_files = []
        nmap_cmd, nmap_output = self.nmap_banner_cmd_from_masscan(
            masscan_output_json_filename)
        if nmap_cmd and nmap_output:
            nmap_results_xml_file1 = self.run_nmap_command(
                nmap_cmd, nmap_output)
            if nmap_results_xml_file1:
                nmap_results_xml_files.append(nmap_results_xml_file1)
        #nmap_results_xml_file2 = self.initial_nmapscan(cidr_list)
        #if nmap_results_xml_file2:
        #    nmap_results_xml_files.append(nmap_results_xml_file2)
        if not nmap_results_xml_files:
            raise Exception("nmap command failed to run.")
        if udp_scan:
            nmap_results_udp_xml_file = self.scan_top_100_udp_ports(cidr_list)
            if not nmap_results_udp_xml_file:
                raise Exception("nmap udp scan failed.")
        return_port_list = []
        return_http_list = []
        for nmap_results_xml_file in nmap_results_xml_files:
            tcp_port_data_list, tcp_http_port_list = self.parse_nmap_xml(
                nmap_results_xml_file, pdns_lookup)
            if tcp_port_data_list:
                return_port_list.extend(tcp_port_data_list)
            if tcp_http_port_list:
                return_http_list.extend(tcp_http_port_list)
        if udp_scan:
            udp_port_data_list, _ = self.parse_nmap_xml(
                nmap_results_udp_xml_file, pdns_lookup)
            if udp_port_data_list:
                return_port_list.extend(udp_port_data_list)
        if return_port_list:
            return_port_list = list(set(return_port_list))
        if return_http_list:
            return_http_list = list(set(return_http_list))
        return return_port_list, return_http_list

    def save_report(self, cidr_list, udp_scan=False, pdns_lookup=False):
        return_port_list, return_http_list = self.seance(
            cidr_list, udp_scan, pdns_lookup)
        csv_columns = ["ip_addr", "status", "protocol", "port", "service-banner"]
        attack_surface_output_ports_filename = os.path.join(
            self.base_dir,
            f"{self.customer_name}_attack_surface_ports_{datetime.datetime.now().isoformat()}.csv")
        attack_surface_output_url_filename = os.path.join(
            self.base_dir,
            f"{self.customer_name}_attack_surface_urls_{datetime.datetime.now().isoformat()}.csv")
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
            self.base_dir,
            f"{self.customer_name}_nmap_rtsp_{datetime.datetime.now().isoformat()}.xml")
        nmap_input_filename = os.path.join(
            self.base_dir,
            f"{self.customer_name}_rtsp_nmap_ip_list_{datetime.datetime.now().isoformat()}.txt")
        with open(nmap_input_filename, 'w') as f:
            f.write("\n".join(ip_list))
        nmap_cmd_str = f"{self.nmap_bin} -e {self.interface_name} -p554 --script=rtsp-url-brute -T5 -oX {nmap_output_filename} -iL {nmap_input_filename}"
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
                                        if scriptelm.tag == "table" and scriptelm.attrib.get('key') == "discovered":
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
        output_filepath = os.path.join(self.base_dir, f"{rtsp_url.replace('/','_')}.jpg")
        cmd_list = f"{self.FFMPEG_BIN} -y -i {rtsp_url} -f mpegts -frames:v 2 {output_filepath}".split()
        completed_process_obj = subprocess.run(cmd_list)
        if completed_process_obj.returncode == 0:
            return output_filepath
        return ''
    
    def get_rtsp_udp_screenshot(self, rtsp_url):
        output_filepath = os.path.join(self.base_dir, f"{rtsp_url.replace('/','_')}.jpg")
        cmd_list = f"{self.FFMPEG_BIN} -y -i {rtsp_url} -frames:v 2 {output_filepath}".split()
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
        cmd_list = f"{self.sslscan_bin} --xml={random_filename} {domain}".split()
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
        return [],[]
    
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
                        d for d in cipher_list if d and (
                            d.get('@strength') != "strong" and d.get('@strength') != "acceptable") or (
                            d.get("@sslversion") != "TLSv1.2" and d.get("@sslversion") != "TLSv1.3")]
                    if bad_ciphers_list:
                        bad_ciphers_list = [f"{domain}:{d.get('@sslversion')}:{d.get('@cipher')}" for d in bad_ciphers_list]
                cert_dict = ssl_test_results.get('certificates')
                if cert_dict:
                    cert_dict = cert_dict.get('certificate')
                    algo = cert_dict.get('signature-algorithm')
                    if algo != "sha256WithRSAEncryption" and algo != "ecdsa-with-SHA384":
                        cert_problems_dict.update({'signature-algorithm':algo})
                    self_signed = cert_dict.get('self-signed')
                    if self_signed == 'true':
                        cert_problems_dict.update({'self-signed':self_signed})
                    expired = cert_dict.get('expired')
                    if expired == 'true':
                        cert_problems_dict.update({'expired':expired})
                    # TODO: later tackle the issue with CA issues not being trusted
        if cert_problems_dict:
            for k,v in cert_problems_dict.items():
                cert_problems_list.append(f"{domain}:{k}:{v}")
        return bad_ciphers_list,cert_problems_list

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
            self.base_dir,
            f"{self.customer_name}_attack_surface_certs_{datetime.datetime.now().isoformat()}.csv")
        attack_surface_output_ciphers_filename = os.path.join(
            self.base_dir,
            f"{self.customer_name}_attack_surface_ciphers_{datetime.datetime.now().isoformat()}.csv")
        if cert_problems_list:
            with open(attack_surface_output_certs_filename, 'w', newline='\n', encoding="utf-8") as csvfile:
                csv_writer = csv.writer(csvfile)
                csv_columns = ["domain","cert_property","value"]
                csv_writer.writerow(csv_columns)
                for cert_row in cert_problems_list:
                    csv_writer.writerow(cert_row.split(":"))
        if bad_ciphers_list:
            with open(attack_surface_output_ciphers_filename, 'w', newline='\n', encoding="utf-8") as urlfile:
                csv_writer = csv.writer(urlfile)
                csv_columns = ["domain","protocol","cipher"]
                csv_writer.writerow(csv_columns)
                for cipher_row in bad_ciphers_list:
                    csv_writer.writerow(cipher_row.split(":"))
        return bad_ciphers_list,cert_problems_list,attack_surface_output_ciphers_filename,attack_surface_output_certs_filename
    
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
                for k,v in idb_dict.items():
                    if isinstance(v, list):
                        tmp_values_list = list(map(str, v))
                        table_data += "{}: {}\n".format(k,"\n       ".join(tmp_values_list))
                    else:
                        table_data += "{}: {}\n".format(k,v)
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
                self.base_dir,
                f"{self.customer_name}_internetdb_{datetime.datetime.now().isoformat()}.json"
            )
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
        output_recon_json_filename = os.path.join(self.base_dir, f"{self.customer_name}_{domain}.json")
        recon_resource_filename = os.path.join(self.base_dir, f"{self.customer_name}_{domain}.rc")
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
                    for k,v in recon_dict.items():
                        if k == "module":
                            table_data += "\n"
                            continue
                        if v:
                            table_data += "{}: {}\n".format(k,v)
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
