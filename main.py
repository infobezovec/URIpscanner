import re
import json 
import socket
import argparse
import requests
from termcolor import colored
from bs4 import BeautifulSoup


def print_help():
    print('\n|------------------------------- Help --------------------------------|')
    print(  '|Usage: scaner.py <work mode> <scan address> <export mode>            |')
    print(  '|----------------------------- Arguments -----------------------------|')
    print(  '| First  argument: work mode. Available modes at this moment is:      |'
          '\n|   --abuse Using AbuseIPDB                                           |'
          '\n|   --vtotal Using VirustotalAPI                                      |'
          '\n|   --shodan Using Shodan                                             |'
          '\n|   --full Full scan                                                  |'
          '\n|---------------------------------------------------------------------|')
    print(  '| Second argument is:                                                 |'
          '\n|   -i If need to scan file with adresses enter path to file          |'
          '\n|---------------------------------------------------------------------|')
    print(  '| Third argument is: URL or ip address                                |'
          '\n|---------------------------------------------------------------------|')
    print(  '| Fourth  argument is: export mode for report file:                   |'
          '\n|   -r With html report.[Not avaliable]                               |'
          '\n|   -c Report will exporting in to console                            |'
          '\n|---------------------------------------------------------------------|')

def check_responce(response):
    if response.status_code == requests.codes.ok:
        #print(response.text)
        return True
    else:
        print("Error:", response.status_code, response.text)
        return False
    

def convert(lst):
   res_dict = {}
   for i in range(0, len(lst), 2):
       res_dict[lst[i]] = lst[i + 1]
   return res_dict


def get_ip(url):
    response = socket.getaddrinfo(url, 80)
    response = convert(response)

    for value, data in response.items():
        data[4][0]
    
    return data[4][0]

def check_whois(address):
    country = ''
    key_api_ninjas = "ninja-key"
    api_url = 'https://api.api-ninjas.com/v1/whois?domain={}'.format(address)
    response = requests.get(api_url, headers={'X-Api-Key': key_api_ninjas})

    if check_responce(response):
        answer = json.loads(response.text)
        if "name_servers" in answer and isinstance(answer["name_servers"], list):
            name_servers_list = answer["name_servers"]
            for name_server in name_servers_list:
                print(name_server)
        if "registrant_country" in answer:
            country = answer['registrant_country']
            print(country)


    ip_adresses = get_ip(address)
    print(ip_adresses)

    url = "http://ipwho.is/" + str(address)
    response = requests.get(url)
    if check_responce(response):
        print(response.json())


def check_vt(address):
    print(colored("SEARCHING IN VirusTotal FOR: " + address, 'blue'))
    header = {'x-apikey': 'vt_api',}
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{address}"


    response = requests.get(url, headers=header)
    if response.status_code == 200:
        #print(response.json())
        answer = json.loads(response.text)
        answer = answer.get('data')
        answer = answer.get('attributes')
        answer = answer.get('last_analysis_results')

        for key, value in answer.items():
            for keyq, valueq in value.items():
                if keyq == 'result':

                    if valueq == 'clean':
                        print(colored(key, 'green'))
                    else:
                        print(colored(key, 'red'))
                    #print(valueq)
                    

            #buff = answer.get('last_analysis_results')


        with open("parced.json", 'wt') as file:
            file.write(json.dumps(answer, indent=2))
        file.close
    else:
        print(f"Ошибка: {response.status_code}")

def check_abuse(address):
    print(colored("SEARCHING IN ABUSEIPDB FOR: " + address, 'blue'))
    url = f"https://api.abuseipdb.com/api/v2/check"
    headers = { "Key": "abuse api", # Замените YOUR_API_KEY на ваш ключ API от AbuseIPDB
        "Accept": "application/json"}
    payload = {
        "ipAddress": address,
        "maxAgeInDays": 30,  
        "verbose": True
    }

    response = requests.get(url, headers=headers, params=payload)
    if response.status_code == 200:
        data = response.json()
        if 'abuseConfidenceScore' in data['data'] and data['data']['abuseConfidenceScore'] > 0:
            print(colored('IP IN DB: ' + str(address), 'red'))
            return True
    print(colored('IP NOT IN DB: ' + str(address), 'green'))
    return False

def generate_report(address):
    with open("index.html", 'r', encoding='utf-8') as file:
        html_content = file.read()
    
    soup = BeautifulSoup(html_content, 'html.parser')
    target_element = soup.find(id='hname')
    new_element = BeautifulSoup("Tested ip:" + str(address), 'html.parser')
    target_element.append(new_element)
    
    with open("index_new.html", 'w', encoding='utf-8') as file:
        file.write(soup.prettify())

def from_file(filename):
    if isfromfile:
        #print(file_path)
        ip_addresses = open(file_path, "r")
        while True:
            ip = ip_addresses.readline()
            ip = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', ip)
            if not ip:
                break
            if mode == 1:
                check_abuse(ip)
            elif mode == 2:
                check_vt(ip)
            elif mode == 3:
                check_abuse(ip)
                check_vt(ip)

            
            #print(ip.strip())
        ip_addresses.close

def arguments(parser):
    required = parser.add_argument_group('required arguments')
    required.add_argument('-a',type=str, help='using abuseIPDB', default="a")
    required.add_argument('-v', type=str, help='using VirusTotal')
    required.add_argument('-s', type=str, help='using Shodan')
    required.add_argument('-f', type=str, help='using all resources')
    required.add_argument('-i', type=str, help='input ip for test')

    optional = parser.add_argument_group('optional arguments')
    optional.add_argument('-file', help='input file path')
    optional.add_argument('-report', help='generate html report', default='stdout')

    return parser.parse_args()

def validate_address(address):
    ip = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
    url = re.compile(r'')


def main():


    mode = 0
    isfromfile = False
    address = ''
    file_path = ''
    report_mode = 0
    parser = argparse.ArgumentParser(description='IP & URL scanner!')
    args = arguments(parser)
    
    #check_whois(args.i)
    #generate_report(args.i)
    #return

    if args.f:
        check_vt(args.i)
        check_abuse(args.i)  
    elif args.a:
        check_abuse(args.i)
    elif args.v:
        check_vt(args.i)
        print(args.v)
        
    if args.report:
        print(args.report)
    

if __name__ == '__main__':
    main()