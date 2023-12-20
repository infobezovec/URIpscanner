import re
import json 
import argparse
import requests
from termcolor import colored
import bs4


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

def check_vt(address):
    print(colored("SEARCHING IN VirusTotal FOR: " + address, 'blue'))
    header = {'x-apikey': '8aa6e2eb012a25ab90f71b0d15ec3d1e4557acdd91d8c4c161394db421e1e156',}
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
    headers = { "Key": "74ae787b1b0b2dc6d46cfa97aa2b44fea8628475f37069fae84763216685cbfe35a10380973e7ea0", # Замените YOUR_API_KEY на ваш ключ API от AbuseIPDB
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
    shodan_api = ""

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

def main():
    mode = 0
    isfromfile = False
    address = ''
    file_path = ''
    report_mode = 0
    parser = argparse.ArgumentParser(description='IP & URL scanner!')
    args = arguments(parser)


    if args.a:
        check_abuse(args.i)

    if args.v:
        check_vt(args.i)
        print(args.v)
    if args.f:
        check_vt(args.i)
        check_abuse(args.i)
        
    if args.report:
        print(args.report)
    
        

    

   

 

if __name__ == '__main__':
    main()