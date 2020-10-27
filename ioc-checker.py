#!/usr/bin/env python3

##################################################################################################################################
# Script to fetch the Domain and IP data from Risk IQ, VirusTotal API and to scrape the categorization from Symantec site review using selenium.
# Author : Hem aka Cyberdude
##################################################################################################################################

#from argparse import ArgumentParser
#from bs4 import BeautifulSoup
import json
import requests
import os
import ipaddress
from requests.auth import HTTPBasicAuth
from argparse import ArgumentParser
from selenium import webdriver
from time import sleep
from config import user, pwd, apikey
from selenium.webdriver.chrome.options import Options


def parse_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except:
        return False

def get_response (url):
    query_payload = {'query': entity}
    query_headers = {'content-type': 'application/json', 'Accept-Charset': 'UTF-8', 'User-Agent': 'Mozilla/5.0'}

    resp = requests.get(url, params=payload, headers=headers, auth=HTTPBasicAuth(user, pwd))

    jsonResp = resp.json()

    jsonResponse = str(jsonResp).replace('\'', '\"').replace('False', '\"False\"').replace('None', '[]').replace('True', '\"True\"')

    return jsonResponse

def fetch_details(user, pwd, entity):
    # global declaration below so that these variables are available for code inside main()
    global classification, sinkhole, everCompromised, count_of_subdom, dynamicDns, mal_results, osint_results

    URL_passivetotal_root = "https://api.passivetotal.org/v2/enrichment"
    URL_passivetotal_malw = "https://api.passivetotal.org/v2/enrichment/malware"
    URL_passivetotal_osint = "https://api.passivetotal.org/v2/enrichment/osint"

    r = get_response(url=URL_passivetotal_root)

    try:
        pt_dict = json.loads(r)
        classification = pt_dict['classification']
        sinkhole = pt_dict['sinkhole']
        everCompromised = pt_dict['everCompromised']
        count_of_subdom = len(pt_dict['subdomains'])
        dynamicDns = pt_dict['dynamicDns']
    except:
        count_of_subdom = "JSON_Error"
        classification = "JSON_Error"
        dynamicDns = "JSON_Error"

    r = get_response(url=URL_passivetotal_malw)
    
    try:
        pt_dict = json.loads(r)
        mal_results = len(pt_dict['results'])
    except:
        mal_results = 'null'

    r = get_response(url=URL_passivetotal_osint)

    try:
        pt_dict = json.loads(r)
        osint_results = len(pt_dict['results'])
    except:
        osint_results = 'null'

    return classification, sinkhole, everCompromised, count_of_subdom, dynamicDns, mal_results, osint_results


class siteReview():
    def __init__(self):
        chrome_options = Options()
        chrome_options.add_argument("--headless")

        # To instantiate the chrome browser
        self.driver = webdriver.Chrome(options=chrome_options)

    def ioc_search(self, entity):
        # self.driver.get('https://sitereview.bluecoat.com/#/')
        url = 'https://sitereview.bluecoat.com/#/lookup-result/' + entity
        self.driver.get(url)
        # With out this sleep function, the site review rejects the requests. This will help to throttle the requests.
        sleep(6)

        try:
            cat = self.driver.find_element_by_xpath(
                '//*[@id="submissionForm"]/span/span[1]/div/div[2]/span[1]/span')
            if self.driver.find_element_by_xpath('//*[@id="submissionForm"]/span/span[1]/div/div[2]/span[2]/span'):
                cat2 = self.driver.find_element_by_xpath(
                    '//*[@id="submissionForm"]/span/span[1]/div/div[2]/span[2]/span')
                if "Last Time" in cat2.text:
                    category = cat.text
                else:
                    category = cat.text + "|" + cat2.text
            else:
                category = cat.text
        except:
            category = 'error'
        return category


def lst_parse(lst, user, pwd, apikey):
    # bot = siteReview()
    with open(os.path.join(lst), 'r') as f:
        for ent in f:
            entity = ent.strip()
            #print('Processing:', entity)
            fetch_details(user, pwd, entity)

            val = bot.ioc_search(entity)

            # VT Processing

            if (parse_ip(entity)):
                url = 'https://www.virustotal.com/api/v3/ip_addresses/' + entity
                headers = {'x-apikey': apikey}
                response = requests.get(url, headers=headers)
                vtResp = response.json()

                if response.status_code == 200:
                    # print(vtResp)
                    # We are using string replacement below to adjust the JSON response to be loaded into python dictionary
                    # vtResponse = str(vtResp).replace('Let\'s', 'Lets').replace('\'', '\"').replace('None','[]').replace('False','\"False\"').replace('True','\"True\"')
                    vt_str = json.dumps(vtResp['data'])
                    vt_dict = json.loads(vt_str)
                    # print(vt_dict)
                    try:
                        attr = vt_dict['attributes']
                        as_own = attr['as_owner']
                        asn = attr['asn']
                        stats = attr['last_analysis_stats']
                        network = attr['network']
                        reputation = attr['reputation']
                        tags = attr['tags']
                    except:
                        attr = 'null'
                        as_own = 'null'
                        asn = 'null'
                        stats = 'null'
                        network = 'null'
                        reputation = 'null'
                        tags = 'null'
                else:
                    attr = 'VT Error'
                    as_own = 'VT Error'
                    asn = 'VT Error'
                    stats = 'VT Error'
                    network = 'VT Error'
                    reputation = 'VT Error'
                    tags = 'VT Error'

                cats = 'AS Owner' + '-' + str(as_own).replace(',', '') + '|' + 'ASN' + '-' + str(asn) + '|' + 'Stats' + '-' + str(stats).replace(', ', ';').replace('{', '').replace('}', '').replace(
                    '\'', '') + '|' + 'Network' + '-' + str(network) + '|' + 'Reputation Score' + '-' + str(reputation) + '|' + 'Tags' + '-' + str(tags).replace('[', '').replace(']', '')

            else:
                url = 'https://www.virustotal.com/api/v3/domains/' + entity
                headers = {'x-apikey': apikey}
                response = requests.get(url, headers=headers)
                vtResp = response.json()
                if response.status_code == 200:
                    # print(vtResp)
                    # We are using string replacement below to adjust the JSON response to be loaded into python dictionary
                    # vtResponse = str(vtResp).replace('Let\'s', 'Lets').replace('\'', '\"').replace('None','[]').replace('False','\"False\"').replace('True','\"True\"')
                    vt_str = json.dumps(vtResp['data'])
                    vt_dict = json.loads(vt_str)
                    # print(vt_dict)
                    try:
                        attr = vt_dict['attributes']
                        cats = attr['categories']
                        stats = attr['last_analysis_stats']
                        # print(cats)
                        cats = str(cats).replace(', ', '|').replace(
                            '{', '').replace('}', '').replace('\'', '')
                        stats = str(stats).replace(', ', ';').replace(
                            '{', '').replace('}', '').replace('\'', '')
                    except:
                        cats = 'null'
                        stats = 'null'
                else:
                    cats = 'VT Error'
                    stats = 'VT Error'

                vt_data = cats + '|' + stats
                print(entity, classification, sinkhole, everCompromised, count_of_subdom, dynamicDns, mal_results,
                      osint_results, vt_data, val, sep=",")


def cmd_parse(cmd, user, pwd, apikey):
    entity = cmd
    fetch_details(user, pwd, entity)
    bot = siteReview()
    val = bot.ioc_search(entity)

    # VT Processing

    if (parse_ip(entity)):
        url = 'https://www.virustotal.com/api/v3/ip_addresses/' + entity
        headers = {'x-apikey': apikey}
        response = requests.get(url, headers=headers)
        vtResp = response.json()
        if response.status_code == 200:
            # print(vtResp)
            # We are using string replacement below to adjust the JSON response to be loaded into python dictionary
            # vtResponse = str(vtResp).replace('Let\'s', 'Lets').replace('\'', '\"').replace('None','[]').replace('False','\"False\"').replace('True','\"True\"')
            vt_str = json.dumps(vtResp['data'])
            vt_dict = json.loads(vt_str)
            # print(vt_dict)
            try:
                attr = vt_dict['attributes']
                as_own = attr['as_owner']
                asn = attr['asn']
                stats = attr['last_analysis_stats']
                network = attr['network']
                reputation = attr['reputation']
                tags = attr['tags']
            except:
                attr = 'null'
                as_own = 'null'
                asn = 'null'
                stats = 'null'
                network = 'null'
                reputation = 'null'
                tags = 'null'
        else:
            attr = 'VT Error'
            as_own = 'VT Error'
            asn = 'VT Error'
            stats = 'VT Error'
            network = 'VT Error'
            reputation = 'VT Error'
            tags = 'VT Error'

        cats = 'AS Owner' + '-' + str(as_own).replace(',', '') + '|' + 'ASN' + '-' + str(
            asn) + '|' + 'Stats' + '-' + str(stats).replace(', ', ';').replace('{', '').replace('}',
                                                                                                '').replace(
            '\'', '') + '|' + 'Network' + '-' + str(network) + '|' + 'Reputation Score' + '-' + str(
            reputation) + '|' + 'Tags' + '-' + str(tags).replace('[', '').replace(']', '')
        print(entity, classification, sinkhole, everCompromised, count_of_subdom, dynamicDns, mal_results,
              osint_results, cats, val, sep=",")

    else:
        url = 'https://www.virustotal.com/api/v3/domains/' + entity
        headers = {'x-apikey': apikey}
        response = requests.get(url, headers=headers)
        vtResp = response.json()
        if response.status_code == 200:
            # print(vtResp)
            # We are using string replacement below to adjust the JSON response to be loaded into python dictionary
            # vtResponse = str(vtResp).replace('Let\'s', 'Lets').replace('\'', '\"').replace('None','[]').replace('False','\"False\"').replace('True','\"True\"')
            vt_str = json.dumps(vtResp['data'])
            vt_dict = json.loads(vt_str)
            # print(vt_dict)
            try:
                attr = vt_dict['attributes']
                cats = attr['categories']
                # print(cats)
                cats = str(cats).replace(', ', '|').replace(
                    '{', '').replace('}', '').replace('\'', '')
            except:
                cats = 'null'
        else:
            cats = 'VT Error'

        test = {
            "ioc": entity,
            "classification": classification,
            "sinkhole": sinkhole,
            "ever_compromised": everCompromised,
            "count_of_subdom": count_of_subdom,
            "dynamic_dns": dynamicDns,
            "mal_results": mal_results,
            "osint_results": osint_results,
            "VT_Data": cats,
            "Symantec_Sitereview": val
        }

        print(test)
        # print(entity, classification, sinkhole, everCompromised, count_of_subdom, dynamicDns, mal_results, osint_results, cats, val, sep=",")


def main():
    p = ArgumentParser()
    p.add_argument("-l", "--lst", type=str, help="Submit domain/IP list separated by new line specifying the absolute path of file")
    p.add_argument("-c", "--cmd", type=str, help="Enter the single domain/IP")
    args = p.parse_args()

    if args.lst:
        # print('ioc,classification,sinkhole,everCompromised,subdomains,dynamicDns,mal_results,osint_results,VT_Data,Symantec_Sitereview')
        lst_parse(args.lst, user, pwd, apikey)
    elif args.cmd:
        # print('ioc,classification,sinkhole,everCompromised,subdomains,dynamicDns,mal_results,osint_results,VT_Data,Symantec_Sitereview')
        cmd_parse(args.cmd, user, pwd, apikey)
    else:
        print("\n" + "Note: Please supplement the single domain/IP by using switch -c or a list of domains/IPs with the path by using switch -l" + "\n")


if __name__ == "__main__":

