import json
import pandas as pd
import resolver

import dns.message
import dns.name
import dns.query
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.zone
from dns.name import from_text
import dns.resolver

from ipaddress import ip_address, IPv6Address

ROOT_SERVERS = ("198.41.0.4",
                "170.247.170.2",
                "192.33.4.12",
                "199.7.91.13",
                "192.203.230.10",
                "192.5.5.241",
                "192.112.36.4",
                "198.97.190.53",
                "192.36.148.17",
                "192.58.128.30",
                "193.0.14.129",
                "199.7.83.42",
                "202.12.27.33")

# data_file = open('resolutions_copy2.json', 'r')
# data = json.load(data_file)

'''
open raw-data.json -> data (dict)
new dataframe -> results (df)

for domain in tranco_top_1M:
    data[domain]
'''

import json
import pandas as pd

# def is_ipv6(ip:str):
#     return ":" in ip

def is_ipv6(ip:str):
    return type(ip_address(ip)) is IPv6Address

    
def parse_zone_file(file_path):
    domain_ns = {}
    with open(file_path, 'r') as file:
        for line in file:
            if 'in ns' in line:
                parts = line.split()
                domain = parts[0].strip()
                ns = parts[4].strip()
                if domain not in domain_ns:
                    domain_ns[domain] = set()
                domain_ns[domain].add(ns)
    return domain_ns



def is_resolvable(data, domain, q_ip, max_depth=10, seen_ips=None):
    """Recursively resolve domain starting from the given query IP."""
    if seen_ips is None:
        seen_ips = set()

    if max_depth <= 0 or q_ip in seen_ips:
        return False, set(), set()  # Return empty sets for both IPv4 and IPv6
    seen_ips.add(q_ip)
    response = data.get(domain, {}).get(q_ip, {})
    ipv4s = set()
    ipv6s = set()

    # Check the 'Answer' section for IPv4 and IPv6 addresses
    if "Answer" in response:
        for ip in response["Answer"].get(domain, []):
            try:
                if is_ipv6(ip):
                    ipv6s.add(ip)  # Add to IPv6 set if IPv6 is found
                else:
                    ipv4s.add(ip)  # Add to IPv4 set if IPv4 is found
            except:
                continue

    # Continue searching in the 'Additional' section
    if "Additional" in response:
        for ip_list in response["Additional"].values():
            for ip in ip_list:
                if ip not in seen_ips:
                    resolvable, more_ipv4s, more_ipv6s = is_resolvable(data, domain, ip, max_depth - 1, seen_ips)
                    ipv4s.update(more_ipv4s)  # Update the IPv4 set with new found IPv4 addresses
                    ipv6s.update(more_ipv6s)  # Update the IPv6 set with new found IPv6 addresses

    return bool(ipv4s or ipv6s), list(ipv4s), list(ipv6s)  # Return True if any IP is found, convert sets to lists



def initial_resolvability():
    # data_file = open('resolutions.json', 'r')
    # # data_file = open('quick_resolutions.json', 'r')
    # data = json.load(data_file)
    with open('resolutions_10k.json', 'r') as file:
        data = json.load(file)

    results = []
    for domain in data:
        root_ip = list(data[domain].keys())[0]
        resolvable, ipv4s, ipv6s = is_resolvable(data, domain, root_ip)
        results.append({
            'Domain': domain,
            'IPv4 Resolvable': bool(ipv4s),
            'IPv6 Resolvable': bool(ipv6s),
            'IPv4': ipv4s,  # Use the list of IPv4 addresses
            'IPv6': ipv6s   # Use the list of IPv6 addresses
        })

    df_results = pd.DataFrame(results)
    df_results.to_csv('domain_resolvability_10k.csv', index=False)
    print("Resolvability results have been saved to CSV files.")



################## secondary portion #######################

def get_out_of_zone_NSes():
    data_file = open('resolutions_10k.json', 'r')
    #data_file = open('quick_resolutions.json', 'r')
    raw_data = json.load(data_file)
    resolve_data = pd.read_csv('domain_resolvability_10k.csv')

    all_ns_entries = []  # list to collect all NS entries

    for index, row in resolve_data.iterrows():
        if row['IPv6 Resolvable'] == False:
            dn = row['Domain']
            for ip in raw_data[dn]:
                if ip not in ROOT_SERVERS:
                    authority_ns_list = []
                    try:
                        authority_ns_list = raw_data[dn][ip]["Authority"][dn]
                    except:
                        authority_ns_list = []

                    additional_ns_list = []
                    try:
                        additional_ns_list = raw_data[dn][ip]["Additional"]
                    except:
                        additional_ns_list = []

                    for ns in authority_ns_list:
                        if ns not in additional_ns_list:
                            all_ns_entries.append({'Domain': dn, 'NameServer': ns})
                            # if dn in NSes_to_check:
                            #     if ns not in NSes_to_check[dn]:
                            #         NSes_to_check[dn].append(ns)
                            #     else:
                            #         continue
                            # else:
                            #     NSes_to_check[dn] = [ns]

    df = pd.DataFrame(all_ns_entries)
    df.to_csv('out_of_zone_nses_10k.csv', index=False)
    print(df)


def ips_from_response(response):
    if response is not None and response.answer:
        for rrset in response.answer:
            value = [str(r) for r in rrset]
            domain_ips = value
            return domain_ips
    return []


def check_out_of_zone_NSes():
    df = pd.read_csv("out_of_zone_nses_10k.csv")
    ns_resolutions_file = open('secondary_resolutions_10k.json', 'r')
    ns_res_data = json.load(ns_resolutions_file)
    df_out = pd.read_csv("domain_resolvability_10k.csv")

    for index, row in df.iterrows():
        dn = row['Domain']
        ns = row['NameServer']
        root_ip = list(ns_res_data[ns].keys())[0]
        resolvable, ipv4s, ipv6s = is_resolvable(ns_res_data, ns, root_ip)

        if bool(ipv6s):
            domain_ipv4s = []
            domain_ipv6s = []

            for ipv4 in ipv4s:
                responseA = resolver.queryServer(dn, dns.rdatatype.A, ipv4)
                responseAAAA = resolver.queryServer(dn, dns.rdatatype.AAAA, ipv4)

                domain_ipv4s = ips_from_response(responseA)
                domain_ipv6s = ips_from_response(responseAAAA)
            
                if domain_ipv6s != []:
                    index = df_out[df_out['Domain'] == dn].index[0]
                    df_out.at[index, 'IPv6 Resolvable'] = bool(ipv6s)
                    df_out.at[index, 'IPv6'] = domain_ipv6s
    
                    df_out.to_csv('domain_resolvability.csv', index=False) ########### wrong file? but not being made anyway?
                    continue


                    
def secondary_resolvability():
    get_out_of_zone_NSes()
    resolver.NS_collect()
    check_out_of_zone_NSes()



def main():
    initial_resolvability()
    secondary_resolvability()


if __name__ == "__main__":
    main()
