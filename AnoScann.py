# Author: Karan Kohale
# Date: 29th April 2023
# Purpose: Kali Linux tool for scanning files and checking their VirusTotal reputation

import hashlib
import requests
import os
import pyfiglet
from termcolor import colored

def ascii_banner(text):
    ascii_banner = pyfiglet.figlet_format(text, font = "slant")
    return ascii_banner

def calculate_hash(file_path):
    with open(file_path, 'rb') as file:
        file_bytes = file.read()
        md5_hash = hashlib.md5(file_bytes).hexdigest()
        sha256_hash = hashlib.sha256(file_bytes).hexdigest()
    return md5_hash, sha256_hash

def get_virustotal_reputation(api_key, file_hash):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {
        "x-apikey": api_key
    }
    response = requests.get(url, headers=headers)
    response_json = response.json()
    try:
        reputation = response_json['data']['attributes']['last_analysis_stats']['malicious']
    except KeyError:
        reputation = "N/A"
    return reputation, response_json['data']['id']

def main():
    print(colored(ascii_banner("AnoScann"), 'red'))
    print(f"\nCreated By Karan Kohale")
    file_path = input("Enter the path of the file you want to scan: ")
    md5_hash, sha256_hash = calculate_hash(file_path)
    print(f"\nMD5 Hash: {md5_hash}")
    print(f"SHA-256 Hash: {sha256_hash}\n")
    api_key = input("Enter your VirusTotal API key: ")
    reputation, file_id = get_virustotal_reputation(api_key, md5_hash)
    if reputation == "N/A":
        print("No reputation found on VirusTotal.")
    elif reputation >= 1:
        print(colored(f"VirusTotal Reputation: {reputation}. This file seems to be malicious.", 'red'))
        print(f"View the VirusTotal graph for this file at: https://www.virustotal.com/gui/file/{file_id}")
    else:
        print(f"VirusTotal Reputation: {reputation}. This file seems to be safe.")

if __name__ == '__main__':
    main()
