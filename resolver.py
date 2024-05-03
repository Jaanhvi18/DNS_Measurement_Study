"""

Source: git@github.com:rohitn212/Recursive-DNS-Resolver.git

"""

import json
import csv
import argparse

import dns.message
import dns.name
import dns.query
import dns.rdata
import dns.rdataclass
import dns.rdatatype

import dns.zone
from dns.name import from_text

import pandas as pd
import dns.resolver
import ipaddress
from ipaddress import ip_address
import pandas as pd


FORMATS = (("CNAME", "{alias} is an alias for {name}"),
           ("A", "{name} has address {address}"),
           ("AAAA", "{name} has IPv6 address {address}"),
           ("MX", "{name} mail is handled by {preference} {exchange}"),
           ("NS", "{name} name server is {target}"),
           ("SOA", "{name} has SOA record {mname} {rname} {serial} {refresh} {retry} {expire} {minimum}"))

# break up the domain name 
# for eca component of the domain name nd the common 

# updated as of  March 25, 2024 : source: https://www.internic.net/domain/named.root
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


simple_cache = {}
sophis_cache = {}
data = {}
bad_queries = {}
df = pd.DataFrame(columns=["queried to", "qType", "exception"])


def collect_results(name: str, check_ipv6: bool = False) -> dict:
    list = []
    if name in simple_cache:
        return simple_cache[name]

    full_response = {}
    target_name = dns.name.from_text(name)
    glue_records = []  # Initialize outside of the for loop

    # Lookup different record types and collect them
    # for record_type in [dns.rdatatype.CNAME, dns.rdatatype.A, dns.rdatatype.AAAA]: #, dns.rdatatype.NS]:
    for record_type in [dns.rdatatype.A, dns.rdatatype.AAAA]:
        response = lookup(target_name, record_type)
        # print(response)
        if "Aditional" in full_response:
            full_response["Aditional"].append(response.additional)
        else:
            full_response["Aditional"]= response.additional
        if "Authority" in full_response:
            full_response["Authority"].append(response.additional)
        else:
            full_response["Authority"]= response.additional
        if not response:
            continue

        if record_type == dns.rdatatype.CNAME:
            cnames = [{"name": target_name, "alias": name} for answer in response.answer for _ in answer]
            full_response["CNAME"] = cnames

        elif record_type == dns.rdatatype.A:
            arecords = [{"name": answer.name, "address": str(rdata)} for answer in response.answer for rdata in answer if rdata.rdtype == dns.rdatatype.A]
            full_response["A"] = arecords

        elif record_type == dns.rdatatype.AAAA:
            aaaarecords = [{"name": answer.name, "address": str(rdata)} for answer in response.answer for rdata in answer if rdata.rdtype == dns.rdatatype.AAAA]
            full_response["AAAA"] = aaaarecords

        elif record_type == dns.rdatatype.NS:
            nsrecords = [{"name": target_name, "target": str(rdata)} for answer in response.answer for rdata in answer if rdata.rdtype == dns.rdatatype.NS]
            full_response["NS"] = nsrecords
        

        for additional in response.additional:
            for record in additional:
                if record.rdtype in [dns.rdatatype.A, dns.rdatatype.AAAA]:
                    glue_records.append({"name": additional.name, "address": str(record)})
        full_response["GLUE"] = glue_records
    
    simple_cache[name] = full_response

    
    return full_response

                    
    

def lookup(target_name: dns.name.Name, qtype: dns.rdata.Rdata) -> dns.message.Message:
    split = str(target_name).split(".")
    domain = split[len(split)-2]
    if domain not in sophis_cache:
        sophis_cache[domain] = {}
    response = None
    for r_server in ROOT_SERVERS:
        if r_server in sophis_cache[domain]:
            response = sophis_cache[domain][r_server]
            # print(f"Cache hit for {domain} at {r_server}")
        else:
            response = queryServer(target_name, qtype, r_server)
            sophis_cache[domain][r_server] = response
            simple_cache[target_name] = response
        if response:
            # print(f"Response from {r_server} for {target_name}/{dns.rdatatype.to_text(qtype)}:\n{response}")
            if response.answer:
                return response
            elif response.additional:
                for additional in response.additional:
                    # if additional.rdtype != 1 and additional.rdtype != 28:  # Focus on A records in 'additional', 1 = A records
                        # continue###################################
                    for add in additional:
                        ##############################
                        to_data(target_name, qtype, str(r_server), response)
                        ##############################
                        if add.rdtype == dns.rdatatype.A:
                            new_response = lookupRecursive(target_name, qtype, str(add))

                if new_response:
                    return new_response
    return None




def to_data(target_name: dns.name.Name, qtype: dns.rdata.Rdata, ipAddr: str, response: dns.message.Message):
    if target_name not in data:
        data[target_name] = {}
        # create new entries

    if ipAddr not in data[target_name]:
        data[target_name][ipAddr] = {}

    entry = data[target_name][ipAddr]
    entry["QUERIED FOR"] = dns.rdatatype.to_text(qtype)


    if response.authority:
        authority_info = parseAuthority(response)
        if "Authority" in entry:
            for key, values in authority_info.items():
                if key in entry["Authority"]:
                    entry["Authority"][key].update(values)
                else:
                    entry["Authority"][key] = values
        else:
            entry["Authority"] = authority_info


    if response.additional:
        additional_info = parseAdditional(response)
        if "Additional" in entry:
            for key, values in additional_info.items():
                if key in entry["Additional"]:
                    entry["Additional"][key].update(values)
                else:
                    entry["Additional"][key] = values
        else:
            entry["Additional"] = additional_info


    if response.answer:
        answer_info = parseAnswer(response)
        if "Answer" in entry:
            for key, values in answer_info.items():
                if key in entry["Answer"]:
                    for value in values:
                        if value not in entry["Answer"][key]:
                            entry["Answer"][key].append(value)
                #     entry["Answer"][key].extend(values)#.unique
                else:
                    entry["Answer"][key] = values
        else:
            entry["Answer"] = answer_info





def queryServer(target_name: dns.name.Name, qtype: dns.rdata.Rdata, ipAddr: str) -> dns.message.Message:
    """
    Makes a udp query to a given IP address, takes care of exceptions, and prints the raw query result.
    """

    outbound_query = dns.message.make_query(target_name, qtype)
    response = None
    ######
    try:
        if (target_name, ipAddr, qtype) in bad_queries:
            return bad_queries[(target_name, ipAddr, qtype)]
    except:
        pass
    ######
    try:
        response = dns.query.udp(outbound_query, ipAddr, 3)
        # print(f"Query to {ipAddr} for {target_name}/{dns.rdatatype.to_text(qtype)}:\n{response}")
    except Exception as e:
        print(f"Error querying {ipAddr} for {target_name}/{dns.rdatatype.to_text(qtype)}: {e}")
        ###############
        if str(e) == "The DNS operation timed out.":
            bad_queries[(target_name, ipAddr, qtype)] = response
        ###############
        
        # {dns.rdatatype.to_text(qtype): e}
        # data[target_name][ipAddr].update({dns.rdatatype.to_text(qtype): e})
    return response


def parseAnswer(response):
    answer_dict = {}
    for rrset in response.answer:
        key = str(rrset.name)
        value = [str(r) for r in rrset]
        answer_dict[key] = value
    return answer_dict


def parseAuthority(response):
    authority_dict = {}
    for rrset in response.authority:
        key = str(rrset.name)
        if key in authority_dict:
            value = set(str(r) for r in rrset) 
            authority_dict[key].update(value)   # converting to a  set to remove duplicates
        else:
            value = set(str(r) for r in rrset)
            # print("\n\n", value,)
            authority_dict[key] = value
    return authority_dict


def parseAdditional(response):
    additional_dict = {}
    for rrset in response.additional:
        key = str(rrset.name)
        if key in additional_dict:
            value = set(str(r) for r in rrset) # converting to a  set to remove duplicates
            additional_dict[key].update(value) 
        else:
            value = set(str(r) for r in rrset)
            # print("\n\n", value,)
            additional_dict[key] = value
    return additional_dict


def parseDomain(response):
    for rrset in response.authority:
        key = str(rrset.name)
        return key


def lookupRecursive(target_name: dns.name.Name,
                    qtype: dns.rdata.Rdata,
                    ipAddr: str, max_depth=3) -> dns.message.Message: ### ADD MAX RECURSION DEPTH
    """
    Recursive lookup that starts from TLD and goes to the lowest level
    """
    response = queryServer(target_name, qtype, ipAddr)
    if response:
        if response.answer:
            #######################
            to_data(target_name, qtype, ipAddr, response)
            ########################
            # for answer in response.answer:
                # if answer.rdtype == 5 and qtype != 5:    # CNAME = 5
                #     target_name = dns.name.from_text(str(answer[0]))
                #     return lookup(target_name, qtype)
            return response
        elif response.additional:
            for additional in response.additional:
                # if additional.rdtype != 1 and additional.rdtype != 28:
                #     continue  #----> not sure if we need to need/want 
                # to focus on a speffic record type in the additonal section
                for add in additional:
                    ##############################
                    to_data(target_name, qtype, ipAddr, response)
                    ##############################
                    if add.rdtype == dns.rdatatype.A:
                        if max_depth <= 0:
                            return response
                        new_response = lookupRecursive(target_name, qtype, str(add), max_depth-1)
            if new_response:
                return new_response

    return response            


def load_csv(filename, num_rows):
    df = pd.read_csv(filename, names=['Rank', 'DN'])
    df = df.iloc[0:num_rows]
    return df


# helper function  checking for sets and converting them to lists.
def convert_sets_to_lists(obj):
    if isinstance(obj, set):
        return list(obj)
    elif isinstance(obj, dict):
        return {k: convert_sets_to_lists(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [convert_sets_to_lists(v) for v in obj]
    return obj


def NS_collect():
    filename = 'secondary_resolutions_10k.json'

    df = pd.read_csv("out_of_zone_nses.csv") ################# update name when made
    for index, row in df.iterrows():
        dn = row['NameServer']
        try:
            collect_results(dn, check_ipv6=True)
        except Exception as e:
            print(f"Error processing domain {dn}: {e}")
        
        if (index % 5 == 0):
            simple_cache = {}
            sophis_cache = {}
            bad_queries = {}
            data_str_keys = {str(key): convert_sets_to_lists(value) for key, value in data.items()}
            with open(filename, 'w') as jsonfile:
                json.dump(data_str_keys, jsonfile, indent=4)
                
    # Last update when finished
    data_str_keys = {str(key): convert_sets_to_lists(value) for key, value in data.items()}
    with open(filename, 'w') as jsonfile:
        json.dump(data_str_keys, jsonfile, indent=4)


def tranco_collect():
    filename = 'resolutions_not.json'

    df = load_csv("top-1m.csv", 250000)
    for index, row in df.iterrows():
    # ######################
    # row_num = 449
    # #row = df.iloc[5800]
    # for i in range(51):
    #     row = df.iloc[row_num + i]
    #     #################
        dn = row['DN']
        try:
            collect_results(dn, check_ipv6=True)
        except Exception as e:
            print(f"Error processing domain {dn}: {e}")
        
        if (index % 50 == 0):
        #if (row_num % 1 == 0):
            simple_cache = {}
            sophis_cache = {}
            bad_queries = {}
            # converting sets to lists before the serialization
            data_str_keys = {str(key): convert_sets_to_lists(value) for key, value in data.items()}
            with open(filename, 'w') as jsonfile:
                json.dump(data_str_keys, jsonfile, indent=4)

    # Run when finished just to ensure final outputs contain all desired data
    data_str_keys = {str(key): convert_sets_to_lists(value) for key, value in data.items()}
    with open(filename, 'w') as jsonfile:
        json.dump(data_str_keys, jsonfile, indent=4)
    

def main():
    tranco_collect()
        
        
if __name__ == "__main__":
    main()
