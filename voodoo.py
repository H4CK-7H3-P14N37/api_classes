#!/usr/bin/env python
import os
import re
import csv
# pip install pandas
# pip install "pandas[excel]"
import shutil
import random
import pandas
import netaddr
import requests
import socket
import shodan
import tldextract
import validators
import dns.resolver

class Voodoo:
    def __init__(self, **kwargs):
        self.column_width = 55
        self.hibp_key = ""
        if os.environ.get("HIBPKEY"):
            self.hibp_key = os.environ.get("HIBPKEY")
        elif kwargs.get("HIBPKEY"):
            self.hibp_key = kwargs.get("HIBPKEY")
        self.shodan_key = ""
        if os.environ.get("SHODANKEY"):
            self.shodan_key = os.environ.get("SHODANKEY")
        elif kwargs.get("SHODANKEY"):
            self.shodan_key = kwargs.get("SHODANKEY")
        self.securitytrails_key = ""
        if os.environ.get("SECURITYTRAILSKEY"):
            self.securitytrails_key = os.environ.get("SECURITYTRAILSKEY")
        elif kwargs.get("SECURITYTRAILSKEY"):
            self.securitytrails_key = kwargs.get("SECURITYTRAILSKEY")
        self.google_customsearch_cx = ""
        if os.environ.get("GOOGLECX"):
            self.google_customsearch_cx = os.environ.get("GOOGLECX")
        elif kwargs.get("GOOGLECX"):
            self.google_customsearch_cx = kwargs.get("GOOGLECX")
        self.google_api_key = ""
        if os.environ.get("GOOGLEKEY"):
            self.google_api_key = os.environ.get("GOOGLEKEY")
        elif kwargs.get("GOOGLEKEY"):
            self.google_api_key = kwargs.get("GOOGLEKEY")
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 0.8
        self.resolver.lifetime = 0.8

    def ip_check(self, ip_addr):
        ip_match = re.compile(
            r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$')
        if ip_match.match(ip_addr):
            return True
        return False

    def private_ip_check(self, ip_addr):
        ip_match = re.compile(
            r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$')
        if ip_match.match(ip_addr):
            if netaddr.IPAddress(ip_addr).is_ipv4_private_use(
            ) or netaddr.IPAddress(ip_addr).is_reserved():
                return True
        return False

    def cve_check(self, cve_num):
        cve_match = re.compile('^(CVE|cve)-[0-9]{4}-[0-9]{4,10}$')
        if cve_match.match(cve_num):
            return True
        return False

    def email_check(self, email_addr):
        try:
            user_regex = re.compile(
                # dot-atom
                r"(^[-!#$%&'*+/=?^_`{}|~0-9A-Z]+(\.[-!#$%&'*+/=?^_`{}|~0-9A-Z]+)*\Z"
                # quoted-string
                r'|^"([\001-\010\013\014\016-\037!#-\[\]-\177]|\\[\001-\011\013\014\016-\177])'
                r'*"\Z)',
                re.IGNORECASE,
            )
            domain_regex = re.compile(
                # max length for domain name labels is 63 characters per RFC 1034
                r"((?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+)(?:[A-Z0-9-]{2,63}(?<!-))\Z",
                re.IGNORECASE,
            )
            user_part, domain_part = email_addr.rsplit("@", 1)
            if user_regex.match(user_part) and domain_regex.match(domain_part):
                return True
        except:
            pass
        return False
    
    def domain_check(self, domain_name):
        if validators.domain(domain_name):
            return True
        return False
    
    def expand_cidr_list(self, cidr_list):
        ip_list = []
        for ip_net in cidr_list:
            net_list = netaddr.IPNetwork(ip_net)
            ip_list.extend([str(ip) for ip in net_list])
        return ip_list

    def whois_request(self, ipaddr, server, port=43):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(30)
            sock.connect((server, port))
        except TimeoutError:
            time.sleep(5)
            return self.whois_request(ipaddr, server, port=port)
        ###############################################################
        # some whois servers need parameters that not part of the RFC #
        # de.whois-servers.net = '-T dn,ace domain.com'               #
        # jp.whois-servers.net = 'DOM domain.com/e'                   #
        ###############################################################
        if ipaddr.endswith('.de') and server == 'whois.denic.de':
            sock.send(("-T dn,ace {}\r\n".format(ipaddr)).encode("utf-8"))
        elif ipaddr.endswith('.jp') and server == 'whois.jprs.jp':
            sock.send(("DOM {}/e\r\n".format(ipaddr)).encode("utf-8"))
        elif server == 'whois.cymru.com':
            sock.send(("-v {}\r\n".format(ipaddr)).encode("utf-8"))
        elif server == 'whois.arin.net':
            sock.send(("+ {}\r\n".format(ipaddr)).encode("utf-8"))
        else:
            sock.send(("{}\r\n".format(ipaddr)).encode("utf-8"))
        buff = b""
        while True:
            data = sock.recv(1024)
            if len(data) == 0:
                break
            buff += data
        return buff.decode("utf-8")
    
    def generate_ascii_table(self, header_name, table_data):
        center_distance = int((self.column_width - len(header_name))/2)
        header = "="*self.column_width
        header += "\n"
        header += " "*center_distance
        header += header_name
        header += " "*center_distance
        header += "\n"
        header += "="*self.column_width
        header += "\n"
        header += table_data
        header += "\n"
        header += "="*self.column_width
        header += "\n"
        return header

    def get_whois(self, ip_addr):
        if self.domain_check(ip_addr) or (self.ip_check(ip_addr) and not self.private_ip_check(ip_addr)):
            if ip_addr[0].isalpha():
                ip_addr = tldextract.extract(ip_addr).registered_domain
            try:
                iana_data = self.whois_request(ip_addr, 'whois.iana.org', 43)
                refer = [
                    l.split(':')[1].strip().replace(
                        'whois://',
                        '') for l in iana_data.splitlines() if l.startswith('refer:') or l.startswith('ReferralServer:')][0]
                whois_data = self.whois_request(ip_addr, refer, 43)
                if 'RIPE' in whois_data:
                    whois_data = self.whois_request(ip_addr, 'whois.ripe.net', 43)
                return whois_data
            except BaseException:
                return
        return
    
    def whois_table(self, search_term):
        header_name = "WHOIS"
        whois_result = self.get_whois(search_term)
        if whois_result:
            stripped_data = [l for l in whois_result.splitlines() if ":" in l]
            table_data = "\n".join(stripped_data)
            return self.generate_ascii_table(header_name, table_data)
        return self.generate_ascii_table(header_name, "No Results.\n")

    def get_asn(self, ip_addr):
        if self.ip_check(ip_addr) and not self.private_ip_check(ip_addr):
            asn_str = self.whois_request(ip_addr, 'whois.cymru.com')
            readerpipe = csv.DictReader(asn_str.split("\n"), delimiter='|')
            return_data = list(readerpipe)
            tmp_dict_list = []
            for d in return_data:
                tmp_dict = {}
                for k, v in d.items():
                    tmp_dict.update({
                        k.strip(): v.strip()
                    })
                tmp_dict_list.append(tmp_dict)
            if tmp_dict_list:
                return tmp_dict_list
        return
    
    def asn_table(self, search_term):
        header_name = "ASN"
        asn_result = self.get_asn(search_term)
        if asn_result:
            formatted_data = []
            for asn_dict in asn_result:
                for k,v in asn_dict.items():
                    formatted_data.append("{}: {}".format(k,v))
            table_data = "\n".join(formatted_data)
            return self.generate_ascii_table(header_name, table_data)
        return self.generate_ascii_table(header_name, "No Results.\n")

    def get_cve_data(self, cve_num):
        url = "https://cve.circl.lu/api/cve/"
        headers = {
            "Content-Type": "application/json"
        }
        if self.cve_check(cve_num):
            response = requests.get(
                f"{url}{cve_num}", 
                headers=headers,
                timeout=10,
                )
            if response.ok:
                response_data = response.json()
                return response_data
        return
    
    def cve_table(self, cve_num):
        header_name = "CVE"
        cve_data = self.get_cve_data(cve_num)
        if cve_data:
            stripped_data = [
                "CVSS: {}".format(cve_data.get("cvss")),
                "Published: {}".format(cve_data.get("Published")),
                "Modified: {}".format(cve_data.get("Modified")),
                "Summary: {}".format(cve_data.get("summary")),
                "Link: https://cve.circl.lu/cve/{}".format(cve_num.upper()),
            ]
            table_data = "\n".join(stripped_data)
            return self.generate_ascii_table(header_name, table_data)
        return self.generate_ascii_table(header_name, "No Results.\n")

    def get_greynoise(self, ip_addr):
        url = "https://api.greynoise.io/v3/community/"
        headers = {"Accept": "application/json"}
        if self.ip_check(ip_addr) and not self.private_ip_check(ip_addr):
            response = requests.get(
                f"{url}{ip_addr}",
                headers=headers,
                timeout=10
            )
            response_data = response.json()
            return response_data
        return
    
    def greynoise_table(self, ip_addr):
        header_name = "Greynoise"
        greynoise_data = self.get_greynoise(ip_addr)
        if greynoise_data:
            stripped_data = ["{}: {}".format(k,v) for k,v in greynoise_data.items()]
            table_data = "\n".join(stripped_data)
            return self.generate_ascii_table(header_name, table_data)
        return self.generate_ascii_table(header_name, "No Results.\n")

    def get_haveibeenpwned_result(self, email_addr):
        if not self.hibp_key:
            raise Exception("HIBP key not provided.")
        hibp_headers = {
            "Content-Type": "application/json",
            "hibp-api-key": self.hibp_key
        }
        if self.email_check(email_addr):
            response = requests.get(
                f"https://haveibeenpwned.com/api/v3/breachedaccount/{email_addr}?truncateResponse=false",
                headers=hibp_headers,
                timeout=10
            )
            if response.status_code == 200:
                return response.json()
        return
    
    def haveibeenpwned_table(self, email_addr):
        header_name = "Have I Been Pwned"
        haveibeenpwned_data = self.get_haveibeenpwned_result(email_addr)
        if haveibeenpwned_data:
            stripped_data = []
            for d in haveibeenpwned_data:
                tmp_list = []
                for k,v in d.items():
                    if k in [
                        "Title",
                        "Domain",
                        "BreachDate",
                        "PwnCount",
                        "DataClasses"
                    ]:
                        if isinstance(v, list):
                            tmp_list.append("{}: {}".format(k,",".join(v)))
                        else:
                            tmp_list.append("{}: {}".format(k,v))
                stripped_data.append(tmp_list)
            table_data = ("\n" + "-"*self.column_width + "\n").join(["\n".join(l) for l in stripped_data])
            return self.generate_ascii_table(header_name, table_data)
        return self.generate_ascii_table(header_name, "No Results.\n")


    def get_securitytails_pdns(self, ip_addr):
        if not self.securitytrails_key:
            raise Exception("Security Trails key not provided.")
        url = "https://api.securitytrails.com/v1/domains/list"
        querystring = {"include_ips": "false", "scroll": "false"}
        headers = {
            "Content-Type": "application/json",
            "APIKEY": self.securitytrails_key
        }
        if self.ip_check(ip_addr) and not self.private_ip_check(ip_addr):
            payload = {"filter": {"ipv4": ip_addr}}
            response = requests.post(
                url,
                json=payload,
                headers=headers,
                params=querystring,
                timeout=10
            )
            if response.ok:
                response_data = response.json()
                return response_data
        return

    def get_pdns_list(self, ip_addr):
        records = []
        pdns_results = self.get_securitytails_pdns(ip_addr)
        if pdns_results:
            records = [d.get("hostname") for d in pdns_results.get("records") if d.get("hostname")]
        return records

    
    def pdns_table(self, ip_addr):
        header_name = "Passive DNS"
        pdns_results = self.get_securitytails_pdns(ip_addr)
        if pdns_results:
            records = [d.get("hostname") for d in pdns_results.get("records")[:10] if d.get("hostname")]
            if records:
                record_count = pdns_results.get("record_count")
                table_data = "Total Records: {}\n".format(record_count)
                stripped_data = records
                table_data += "Last 10:\n  "
                table_data += "\n  ".join(stripped_data)
                return self.generate_ascii_table(header_name, table_data)
        return self.generate_ascii_table(header_name, "No Results.\n")
    
    def get_shodan_data(self, ip_addr):
        if not self.shodan_key:
            raise Exception("Shodan key not provided.")
        api = shodan.Shodan(self.shodan_key)
        host_info = {}
        service_results = []
        if self.ip_check(ip_addr) and not self.private_ip_check(ip_addr):
            try:
                host = api.host(ip_addr)
            except shodan.exception.APIError:
                return None,None
            host_info = {
                    "IP": host.get('ip_str'),
                    "Organization": host.get('org', 'n/a'),
                    "Operating System": host.get('os', 'n/a')
                }
            for item in host['data']:
                service_dict = {
                    "Port": item.get('port'),
                    "Banner": item.get('data')
                }
                if service_dict:
                    service_results.append(service_dict)
        return host_info,service_results
    
    def shodan_table(self, ip_addr):
        header_name = "Shodan"
        host_info_dict, service_results_list = self.get_shodan_data(ip_addr)
        if host_info_dict:
            table_data = ""
            for k,v in host_info_dict.items():
                table_data += "{}: {}\n".format(k,v)
            if service_results_list:
                table_data += "Services: \n"
                for service_dict in service_results_list:
                    for k,v in service_dict.items():
                        tmp_value = str(v).strip().replace("\n", "\n          ")
                        table_data += f"  {k}: {tmp_value}\n"
            return self.generate_ascii_table(header_name, table_data)
        return self.generate_ascii_table(header_name, "No Results.\n")

    def get_internetdb_result(self, ip_addr):
        if self.ip_check(ip_addr) and not self.private_ip_check(ip_addr):
            ip_addr_obj = netaddr.IPAddress(ip_addr)
            if ip_addr_obj.is_unicast() and not ip_addr_obj.is_ipv4_private_use():
                response = requests.get(
                    f"https://internetdb.shodan.io/{ip_addr}", timeout=10)
                if response.status_code == 200:
                    return response.json()
        return
    
    def internetdb_table(self, ip_addr):
        header_name = "InternetDB"
        host_info_dict = self.get_internetdb_result(ip_addr)
        if host_info_dict:
            table_data = ""
            for k,v in host_info_dict.items():
                if isinstance(v, list):
                    tmp_values_list = list(map(str, v))
                    table_data += "{}: {}\n".format(k,"\n       ".join(tmp_values_list))
                else:
                    table_data += "{}: {}\n".format(k,v)
            return self.generate_ascii_table(header_name, table_data)
        return self.generate_ascii_table(header_name, "No Results.\n")
    
    def get_twitter_result(self, search_term):
        if not self.google_api_key:
            raise Exception("Google API Key not provided.")
        response = requests.get(
            "https://www.googleapis.com/customsearch/v1", 
            params={
                "key":self.google_api_key,
                "cx":self.google_customsearch_cx,
                "q":search_term
            },
            timeout=0
        )
        if response.status_code == 200:
            return response.json()
        return
    
    def twitter_table(self, search_term):
        header_name = "Twitter"
        twitter_response = self.get_twitter_result(search_term)
        if twitter_response:
            results = []     
            response_items = twitter_response.get("items")
            for item in response_items:
                results.append(
                    "Title: {}\nDescription: {}\nLink: {}\n".format(
                        item.get("title"),
                        item.get("snippet"),
                        item.get("link")
                    )
                )
            if results:
                return self.generate_ascii_table(header_name, "\n\n".join(results))
        return self.generate_ascii_table(header_name, "No Results.\n")
    
    def get_iprep_result(self, cidr):
        response = requests.get(
            "https://iprep.lcrawl.com/api/iprep/", 
            params={
                "cidr": cidr
            },
            timeout=30
        )
        if response.status_code == 200:
            return response.json()
        return
    
    def iprep_table(self, cidr):
        header_name = "IPRep"
        iprep_response = self.get_iprep_result(cidr)
        if iprep_response:
            results = []     
            response_items = iprep_response.get("results")
            for dict_item in response_items:
                tmp_list = []
                for k,v in dict_item.items():
                    if isinstance(v, dict):
                        for kk,vv in v.items():
                            tmp_list.append(
                                "    {}__{}: {}".format(k,kk,vv)
                            )
                    else:
                        tmp_list.append("{}: {}".format(k,v))
                results.append("\n".join(tmp_list))
            if results:
                return self.generate_ascii_table(header_name, "\n\n".join(results))
        return self.generate_ascii_table(header_name, "No Results.\n")

    def get_ns_records(self, domain):
        results_list = []
        try:
            answers = self.resolver.resolve(domain, 'NS')
            for server in answers:
                results_list.append(server.to_text())
        except dns.resolver.NoAnswer:
            pass
        except dns.resolver.LifetimeTimeout:
            pass
        except dns.resolver.NXDOMAIN:
            pass
        return results_list

    def get_a_records(self, domain):
        results_list = []
        try:
            answers = self.resolver.resolve(domain, 'A')
            for server in answers:
                results_list.append(server.address)
        except dns.resolver.NoAnswer:
            pass
        except dns.resolver.LifetimeTimeout:
            pass
        except dns.resolver.NXDOMAIN:
            pass
        return results_list
    
    def get_aaaa_records(self, domain):
        results_list = []
        try:
            answers = self.resolver.resolve(domain, 'AAAA')
            for server in answers:
                results_list.append(server.address)
        except dns.resolver.NoAnswer:
            pass
        except dns.resolver.LifetimeTimeout:
            pass
        except dns.resolver.NXDOMAIN:
            pass
        return results_list
    
    def get_mx_records(self, domain):
        results_list = []
        try:
            answers = self.resolver.resolve(domain, 'MX')
            for server in answers:
                results_list.append(server.to_text())
        except dns.resolver.NoAnswer:
            pass
        except dns.resolver.LifetimeTimeout:
            pass
        except dns.resolver.NXDOMAIN:
            pass
        return results_list
    
    def get_txt_records(self, domain):
        results_list = []
        try:
            answers = self.resolver.resolve(domain, 'TXT')
            for server in answers:
                results_list.append(server.to_text())
        except dns.resolver.NoAnswer:
            pass
        except dns.resolver.LifetimeTimeout:
            pass
        except dns.resolver.NXDOMAIN:
            pass
        return results_list

    def dns_records_table(self, domain):
        header_name = "DNS Records"
        results_list = []
        if self.domain_check(domain):
            a_records = self.get_a_records(domain)
            if a_records:
                a_table = self.generate_ascii_table("A Records", "\n".join(a_records))
                results_list.append(a_table)
            aaaa_records = self.get_aaaa_records(domain)
            if aaaa_records:
                aaaa_table = self.generate_ascii_table("AAAA Records", "\n".join(aaaa_records))
                results_list.append(aaaa_table)
            domain = tldextract.extract(domain).registered_domain
            ns_records = self.get_ns_records(domain)
            if ns_records:
                ns_table = self.generate_ascii_table("NS Records", "\n".join(ns_records))
                results_list.append(ns_table)
            mx_records = self.get_mx_records(domain)
            if mx_records:
                mx_table = self.generate_ascii_table("MX Records", "\n".join(mx_records))
                results_list.append(mx_table)
            txt_records = self.get_txt_records(domain)
            if txt_records:
                txt_table = self.generate_ascii_table("TXT Records", "\n".join(txt_records))
                results_list.append(txt_table)
        if results_list:
            return "\n".join(results_list)
        return self.generate_ascii_table(header_name, "No Results.\n")


    def ascii_ipaddr_results_table(self, search_value):
        results_list = []
        asn_result = self.asn_table(search_value)
        if asn_result:
            results_list.append(asn_result)
        internetdb_result = self.internetdb_table(search_value)
        if internetdb_result:
            results_list.append(internetdb_result)
        whois_result = self.whois_table(search_value)
        if whois_result:
            results_list.append(whois_result)
        if results_list:
            return "\n".join(results_list)
        return "No results."
    
    def ascii_domain_results_table(self, search_value):
        results_list = []
        whois_result = self.whois_table(search_value)
        if whois_result:
            results_list.append(whois_result)
        dns_result = self.dns_records_table(search_value)
        if dns_result:
            results_list.append(dns_result)
        if results_list:
            return "\n".join(results_list)
        return "No results."
    
    def ascii_rep_results_table(self, search_value):
        results_list = []
        # Too slow to return all this at once
        # iprep_result = self.iprep_table(search_value)
        # if iprep_result:
        #    results_list.append(iprep_result)
        greynoise_result = self.greynoise_table(search_value)
        if greynoise_result:
            results_list.append(greynoise_result)
        pdns_result = self.pdns_table(search_value)
        if pdns_result:
            results_list.append(pdns_result)
        if results_list:
            return "\n".join(results_list)
        return "No results."

    def ascii_results_table(self, search_value, short_version=False):
        results_list = []
        if self.domain_check(search_value):
            a_records = self.get_a_records(search_value)
            if a_records:
                a_table = self.generate_ascii_table("A Records", "\n".join(a_records))
                results_list.append(a_table)
            aaaa_records = self.get_aaaa_records(search_value)
            if aaaa_records:
                aaaa_table = self.generate_ascii_table("AAAA Records", "\n".join(aaaa_records))
                results_list.append(aaaa_table)
            domain = tldextract.extract(search_value).registered_domain
            ns_records = self.get_ns_records(domain)
            if ns_records:
                ns_table = self.generate_ascii_table("NS Records", "\n".join(ns_records))
                results_list.append(ns_table)
            mx_records = self.get_mx_records(domain)
            if mx_records:
                mx_table = self.generate_ascii_table("MX Records", "\n".join(mx_records))
                results_list.append(mx_table)
            txt_records = self.get_txt_records(domain)
            if txt_records:
                txt_table = self.generate_ascii_table("TXT Records", "\n".join(txt_records))
                results_list.append(txt_table)
            whois_result = self.whois_table(search_value)
            if whois_result:
                results_list.append(whois_result)
            try:
                search_value = socket.gethostbyname(search_value)
            except socket.gaierror:
                pass
        if self.cve_check(search_value):
            cve_result = self.cve_table(search_value)
            if cve_result:
                results_list.append(cve_result)
        if self.email_check(search_value):
            hibp_result = self.haveibeenpwned_table(search_value)
            if hibp_result:
                results_list.append(hibp_result)
        if self.ip_check(search_value) and not self.private_ip_check(search_value):
            asn_result = self.asn_table(search_value)
            if asn_result:
                results_list.append(asn_result)
            internetdb_result = self.internetdb_table(search_value)
            if internetdb_result:
                results_list.append(internetdb_result)
            whois_result = self.whois_table(search_value)
            if whois_result:
                results_list.append(whois_result)
            iprep_result = self.iprep_table(search_value)
            if iprep_result:
                results_list.append(iprep_result)
            if not short_version:
                greynoise_result = self.greynoise_table(search_value)
                if greynoise_result:
                    results_list.append(greynoise_result)
                pdns_result = self.pdns_table(search_value)
                if pdns_result:
                    results_list.append(pdns_result)
                shodan_result = self.shodan_table(search_value)
                if shodan_result:
                    results_list.append(shodan_result)
        if self.private_ip_check(search_value):
            results_list.append("\nRFC1918 Address\n")
        if results_list:
            return "\n".join(results_list)
    
    def add_asn_data_to_s1_dns_deepviz(self, results_list):
        for result_dict in results_list:
            asn_data = {}
            dns_ip_str = result_dict.get('dnsResponse')
            if dns_ip_str:
                if ';' in dns_ip_str:
                    dns_ip_list = re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\;', dns_ip_str)
                else:
                    dns_ip_list = [dns_ip_str]
                if dns_ip_list:
                    dst_ip = dns_ip_list[0]
                    if dst_ip:
                        tmp_asn_data = self.get_asn(dst_ip)
                        if tmp_asn_data:
                            for k,v in tmp_asn_data[0].items():
                                asn_data.update({f"ASN_{k.replace(' ','')}": v})
            else:
                asn_list = [
                    'AS',
                    'IP',
                    'BGPPrefix',
                    'CC',
                    'Registry',
                    'Allocated',
                    'ASName'
                ]
                for asn_pre in asn_list:
                    asn_data.update({f"ASN_{asn_pre}": ""})
            if asn_data:
                result_dict.update(asn_data)
        return results_list
    
    def create_query_str_for_s1_dnsresponse(self, problem_ip_dict):
        ip_query_list = []
        for _,problem_ip_list in problem_ip_dict.items():
            if problem_ip_list:
                for ip_addr in problem_ip_list:
                    if not self.private_ip_check(ip_addr):
                        ip_query_list.append(f'DnsResponse Contains "{ip_addr}"')
        return ip_query_list
    
    def create_query_str_for_s1_powerquery_filehash(self, file_hash):
        return f'src.process.parent.image.sha1 == "{file_hash}" or src.process.image.sha1 == "{file_hash}" or tgt.process.image.sha1 = "{file_hash}" or tgt.file.sha1 == "{file_hash}"| columns endpoint.name'

    def create_query_str_for_s1_powerquery_filehash_data(self, file_hash):
        return f'(src.process.parent.image.sha1 == "{file_hash}" or src.process.image.sha1 == "{file_hash}" or tgt.process.image.sha1 = "{file_hash}" or tgt.file.sha1 == "{file_hash}")  | group countOfEvents=count() by event.type, endpoint.name , indicator.name,  tgt.file.path, src.process.cmdline,src.process.indicatorExploitationCount   | sort -countOfEvents'

    def create_query_str_for_s1_powerquery_file_path_data(self, file_path):
        # Replacing the \device path with *
        if file_path.lower().startswith("\\device\\harddiskvolume"):
            file_path = re.sub(r'\\device\\harddiskvolume[\*0-9]{1,2}', '*', file_path, flags=re.I)
        # Prepending * to \\ file paths
        #if file_path.lower().startswith("\\"):
        #    file_path = f"*{file_path}"
        # Prepend * to paths that aren't full C drive paths
        # isn't a file extension
        # and isn't *\\
        #if not re.findall(r'^[a-zA-Z]\:',file_path) and not re.findall(r'^\*\.[a-zA-Z]{1,4}$', file_path) and not re.findall(r'^\*\\', file_path):
        #    file_path = f"*{file_path}"
        # adding * to the end of paths
        # that aren't file extensions
        # and aren't ending with exe, bat, dll, etc.
        #if not re.findall(r'^\*\.[a-zA-Z]{1,4}$', file_path) and not re.findall(r'[a-zA-Z]\.[a-zA-Z]{3}$', file_path):
        #    file_path = f"{file_path}*"
        # making the string a regex
        # that aren't file extensions
        if "*" in file_path and not re.findall(r'^\*\.[a-zA-Z]{1,4}$', file_path):
            file_path = file_path.replace(
                "*.*","*"
            ).replace(
                "*",".*"
            ).replace(
                "\\","\\\\\\"
            ).replace(
                "?","\\\\?"
            ).replace(
                ")","\\\\)"
            ).replace(
                "(","\\\\("
            ).replace(
                "}","\\\\}"
            ).replace(
                "{","\\\\{"
            ).replace(
                "+","\\\\+"
            )
        else:
            file_path = file_path.replace(
                "\\","\\\\\\\\"
            ).replace(
                "?","\\\\?"
            ).replace(
                ")","\\\\)"
            ).replace(
                "(","\\\\("
            ).replace(
                "}","\\\\}"
            ).replace(
                "{","\\\\{"
            ).replace(
                "+","\\\\+"
            )
        # replace the * in file extensions with .*
        if re.findall(r'^\*\.[a-zA-Z]{1,4}$', file_path):
            file_path = f"{file_path}$".replace("*",".*")
        # replace multiple .*'s with singles
        if re.findall(r'(\.\*){2,10}', file_path):
            file_path = re.sub(r'(\.\*){2,10}', '.*', file_path, flags=re.I)
        return f'src.process.cmdline matches ("{file_path}") | columns event.type, endpoint.name, indicator.name, src.process.cmdline, src.process.indicatorExploitationCount'

    def get_asn_desc(self, ip_addr):
        asn_dict_list = self.get_asn(ip_addr)
        if asn_dict_list:
            return "|".join([d.get('AS Name').replace(",","") for d in asn_dict_list])
        return

    def get_dns_asn(self, dns_filename):
        output_filename = f"{dns_filename}.csv"
        with open(dns_filename,'r', encoding="utf-8") as f:
            domains = f.read().splitlines()
        with open(output_filename, "w", encoding="utf-8") as f:
            for domain in domains:
                try:
                    response = socket.gethostbyname(domain)
                    asn_data = self.get_asn_desc(response)
                    csv_line = f"{domain},{response},{asn_data}"
                    print(csv_line)
                    f.write(f"{csv_line}\n")
                except socket.gaierror:
                    response = f"{domain},NXDOMAIN,NXASN"
                    print(response)
                    f.write(f"{response}\n")
        return output_filename

    def get_dns_asn_list(self, dns_list):
        response_list = []
        for domain in dns_list:
            try:
                response = socket.gethostbyname(domain)
                asn_data = self.get_asn_desc(response)
                response_list.append(
                    (domain, response,asn_data)
                )
            except socket.gaierror:
                response_list.append(
                    (domain,"NXDOMAIN","NXASN")
                )
        return response_list

    def open_excel_file(self, filename):
        df = pandas.read_excel(filename)
        return df
    
    def open_csv_file(self, filename):
        results_list = []
        with open(filename, newline='') as csvfile:
            rows = csv.DictReader(
                csvfile, 
                delimiter=',',
                quotechar='"',
                dialect="excel"
            )
            results_list = [row for row in rows]
        return results_list
    
    def open_csv_file_as_list(self, filename, delimiter=":"):
        return_list = []
        results_list = self.open_csv_file(filename)
        if results_list:
            return_list = [delimiter.join([k for k,_ in results_list[0].items()])]
            return_list += [delimiter.join([v for k,v in l.items() if v and k]).strip() for l in results_list]
        return return_list
    
    def dirlist_pngs(self, folder_path):
        return [os.path.join(folder_path, f) for f in os.listdir(folder_path) if f.endswith(".png")]
    
    def open_file(self, filename):
        results_list = []
        with open(filename, 'r') as f:
            results_list = f.read().splitlines()
        return results_list

    def open_ansible_ini_file(self, ini_filename):
        inventory_dict = {}
        with open(ini_filename, 'r', encoding='utf-8') as f:
            lines = f.read().splitlines()
        group_name = ''
        for line in lines:
            if line.startswith('['):
                group_name = line.replace('[','').replace(']','')
                inventory_dict.update({group_name:{}})
                continue
            if line.startswith('#'):
                continue
            if line:
                line_list = line.split(' ')
                ip_addr = line_list[0]
                if '=' in ip_addr:
                    inventory_dict[group_name].update({line:{}})
                    continue
                inventory_dict[group_name].update({ip_addr:{}})
                _ = line_list.pop(0)
                for inline_var in line_list:
                    if '=' in inline_var:
                        inline_var_list = inline_var.split('=')
                        key_name = inline_var_list[0]
                        value = inline_var_list[1].replace("'","").replace('"','')
                        inventory_dict[group_name][ip_addr].update({key_name:value})
        return inventory_dict

    def write_openssh_config(self, inventory_dict, groups_to_gen, openssh_config_filename):
        host_title = "#"*50 + \
                "\n### {}\n" + \
                "#"*50 + "\n\n"
        host_written_already = []
        with open(openssh_config_filename, 'w', encoding="utf-8") as f:
            for group_name, host_dict in inventory_dict.items():
                if group_name in groups_to_gen:
                    if host_dict:
                        f.write(host_title.format(group_name.upper()))
                        for host_ip, host_details_dict in host_dict.items():
                            friendly_name = host_details_dict.get('friendly_name')
                            if friendly_name not in host_written_already:
                                normal_username = host_details_dict.get('normal_username')
                                port_num = host_details_dict.get('ansible_port')
                                f.write(f"Host {friendly_name}\n")
                                f.write(f"    HostName {host_ip}\n")
                                if normal_username:
                                    f.write(f"    User {normal_username}\n")
                                if port_num:
                                    f.write(f"    Port {port_num}\n")
                                f.write("\n")
                                host_written_already.append(friendly_name)
        return openssh_config_filename

    def default_openssh_config(self, ini_filename, groups_to_gen, openssh_config_filename):
        inventory_dict = self.open_ansible_ini_file(ini_filename)
        output_filename = self.write_openssh_config(inventory_dict, groups_to_gen, openssh_config_filename)
        return output_filename

    def flatten(self, d):
        out = {}
        for key, val in d.items():
            if isinstance(val, dict):
                val = [val]
            if isinstance(val, list):
                for subdict in val:
                    deeper = self.flatten(subdict).items()
                    out.update({key + '_' + key2: val2 for key2, val2 in deeper})
            else:
                out[key] = val
        return out

    def write_flatten_csv(self, results, csv_name):
        field_keys = []
        for r in results:
            field_keys.extend(list(self.flatten(r).keys()))
        field_keys = list(set(field_keys))
        with open(csv_name, 'w', newline='\n', encoding="utf-8") as csvfile:
            fieldnames = field_keys
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for r in results:
                writer.writerow(self.flatten(r))
        return csv_name
    
    def get_securitytails_pdns_subdomains(self, base_domain):
        if not self.securitytrails_key:
            raise Exception("Security Trails key not provided.")
        url = f"https://api.securitytrails.com/v1/domain/{base_domain}/subdomains"
        headers = {
            "accept": "application/json",
            "APIKEY": self.securitytrails_key
        }
        params = {
            "children_only": False,
            "include_inactive": False
        }
        response = requests.get(url, headers=headers, params=params, timeout=10)
        if response.ok:
            response_data = response.json()
            subdomains = response_data.get('subdomains')
            if subdomains:
                return [f"{d}.{base_domain}" for d in subdomains]
        return []

    def spongemocktext(self, input_text):
        output_text = ""
        for char in input_text:
            if char.isalpha():
                if random.random() > 0.5:
                    output_text += char.upper()
                else:
                    output_text += char.lower()
            else:
                output_text += char
        return output_text

    def zip_dir(self, folder_path, output_filename):
        return shutil.make_archive(output_filename, 'zip', folder_path)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='Voodoo Search')
    parser.add_argument('searchterm', help='input an IP, email address, or CVE to retrieve data on.')
    parser.add_argument('-s', action='store_true', help='short version of output for ASN, PDNS, InternetDB')
    args = parser.parse_args()
    search_term = args.searchterm
    short_version_args = args.s
    obj = Voodoo()
    print(obj.ascii_results_table(search_term, short_version=short_version_args))
