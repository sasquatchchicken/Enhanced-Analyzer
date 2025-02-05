import base64
import math
import requests
import hashlib
import argparse
import json
import re
import csv
from datetime import datetime
import magic
import os
import joblib
from sklearn.ensemble import RandomForestClassifier

# API Keys (Replace with your own)
API_KEYS = {
    "virustotal": "YOUR_VIRUSTOTAL_KEY",
    "abuseipdb": "YOUR_ABUSEIPDB_KEY",
    "alienvault": "YOUR_ALIENVAULT_KEY",
    "ibmxforce": "YOUR_XFORCE_KEY",
    "shodan": "YOUR_SHODAN_KEY"
}

class AIHashClassifier:
    def __init__(self):
        try:
            self.model = joblib.load("hash_model.pkl")  # Pre-trained model
        except FileNotFoundError:
            print("Warning: hash_model.pkl not found! AI classification will be skipped.")
            self.model = None 
            
    def predict_category(self, hash_value):
        if self.model is None:
            return "AI Model Unavailable"
        
        features = [len(hash_value), sum(ord(c) for c in hash_value) % 256]
        prediction = self.model.predict([features])[0]
        return int(prediction)

class ThreatIntelligence:
    def __init__(self):
        self.session = requests.Session()

    def check_virustotal(self, hash_value):
        if not API_KEYS['virustotal']:
            return "API Key Missing"
        print(f"Checking VirusTotal for {hash_value}...")
        url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
        headers = {"x-apikey": API_KEYS['virustotal']}

        try:
            response = self.session.get(url, headers=headers)
            return response.json().get('data', {}) if response.status_code == 200 else "Not Found in VT"
        except requests.exceptions.RequestException as e:
            return f"VirusTotal Request Failed: {e}"

    def check_abuseipdb(self, ip):
        if not API_KEYS['abuseipdb']:
            return "API Key Missing"
        print(f"Checking AbuseIPDB for {ip}...")
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": API_KEYS['abuseipdb'], "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": "90"}

        try:
            response = self.session.get(url, headers=headers, params=params)
            return response.json() if response.status_code == 200 else "No record"
        except requests.exceptions.RequestException as e:
            return f"AbuseIPDB Request Failed: {e}"

    def check_alienvault(self, indicator):
        if not API_KEYS['alienvault']:
            return "API Key Missing"
        print(f"Checking AlienVault for {indicator}...")
        url = f"https://otx.alienvault.com/api/v1/indicators/{indicator}/general"
        headers = {"X-OTX-API-KEY": API_KEYS['alienvault']}

        try:
            response = self.session.get(url, headers=headers)
            return response.json() if response.status_code == 200 else "No record"
        except requests.exceptions.RequestException as e:
            return f"AlienVault Request Failed: {e}"

    def check_xforce(self, hash_value):
        if not API_KEYS['ibmxforce']:
            return "API Key Missing"
        print(f"Checking IBM X-Force for {hash_value}...")
        url = f"https://api.xforce.ibmcloud.com/malware/{hash_value}"
        headers = {"Accept": "application/json", "Authorization": f"Bearer {API_KEYS['ibmxforce']}"}

        try:
            response = self.session.get(url, headers=headers)
            return response.json() if response.status_code == 200 else "No record"
        except requests.exceptions.RequestException as e:
            return f"X-Force Request Failed: {e}"

    def check_shodan(self, ip):
        if not API_KEYS['shodan']:
            return "API Key Missing"
        print(f"Checking Shodan for {ip}...")
        url = f"https://api.shodan.io/shodan/host/{ip}?key={API_KEYS['shodan']}"

        try:
            response = self.session.get(url)
            return response.json() if response.status_code == 200 else "No record"
        except requests.exceptions.RequestException as e:
            return f"Shodan Request Failed: {e}"

class ForensicAnalyzer:
    def __init__(self):
        self.session = requests.Session()

    def calculate_entropy(self, data):
        if not data:
            return 0
        frequency = {byte: data.count(byte) for byte in set(data)}
        return -sum((count / len(data)) * math.log2(count / len(data)) for count in frequency.values())

    def analyze_artifacts(self, data):
        analysis = {
            "hashes": {
                "md5": hashlib.md5(data).hexdigest(),
                "sha1": hashlib.sha1(data).hexdigest(),
                "sha256": hashlib.sha256(data).hexdigest(),
            },
            "embedded_ips": re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', data.decode(errors="ignore")),
            "embedded_urls": re.findall(r'https?://[^\s/$.?#].[^\s]*', data.decode(errors="ignore")),
            "embedded_domains": re.findall(r'([a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}', data.decode(errors="ignore")),
        }
        return analysis

class base64Analyzer:
    def __init__(self):
        self.forensic = ForensicAnalyzer()
        self.threat = ThreatIntelligence()
        self.ai_classifier = AIHashClassifier()

    def decode_data(self, encoded_data):
        try:
            encoded_data = encoded_data.replace('-', '+').replace('_', '/')
            missing_padding = len(encoded_data) % 4
            if missing_padding:
                encoded_data += '=' * (4 - missing_padding)
            return base64.b64decode(encoded_data)
        except Exception as e:
            raise ValueError(f"Decoding error: {str(e)}")

    def comprehensive_analysis(self, encoded_data):
        try:
            decoded_data = self.decode_data(encoded_data)

            analysis = {
                "basic_analysis": {
                    "length": len(decoded_data),
                    "entropy": self.forensic.calculate_entropy(decoded_data),
                    "hex_representation": decoded_data.hex(),
                },
                "forensic_analysis": self.forensic.analyze_artifacts(decoded_data),
                "threat_intel": {},
                "ai_prediction": self.ai_classifier.predict_category(decoded_data.hex())
            }

            sha256_hash = analysis["forensic_analysis"]["hashes"]["sha256"]
            analysis["threat_intel"]["virustotal"] = self.threat.check_virustotal(sha256_hash)
            analysis["threat_intel"]["ibm_xforce"] = self.threat.check_xforce(sha256_hash)

            abuseipdb_results = {}
            alienvault_results = {}
            shodan_results = {}

            for ip in analysis["forensic_analysis"]["embedded_ips"]:
                abuseipdb_results[ip] = self.threat.check_abuseipdb(ip)
                shodan_results[ip] = self.threat.check_shodan(ip)
                alienvault_results[ip] = self.threat.check_alienvault(ip)

            if not analysis["forensic_analysis"]["embedded_ips"]:
                abuseipdb_results["No IP"] = self.threat.check_abuseipdb("192.0.2.1")  #<----this IP is a placeholder 
                shodan_results["No IP"] = self.threat.check_shodan("192.0.2.1")
                alienvault_results["No IP"] = self.threat.check_alienvault("192.0.2.1")
                    
            analysis["threat_intel"]["abuseipdb"] = abuseipdb_results
            analysis["threat_intel"]["shodan"] = shodan_results
            analysis["threat_intel"]["alienvault"] = alienvault_results
            return analysis
        except Exception as e:
            return {"error": str(e)}

def export_iocs(analysis, output_file):
    with open(output_file, "w") as f:
        json.dump(analysis, f, indent=4)
    print(f"IOCs saved to {output_file}")

def main():
    parser = argparse.ArgumentParser(description="Advanced Base64 Threat Analysis Tool")
    parser.add_argument("-i", "--input", help="Base64 encoded string")
    parser.add_argument("-f", "--file", help="Input file containing Base64 data")
    parser.add_argument("-o", "--output", help="Output file for report")

    args = parser.parse_args()
    
    encoded_data = args.input if args.input else open(args.file, "r").read()

    analyzer = base64Analyzer()
    analysis = analyzer.comprehensive_analysis(encoded_data.strip())

    print(json.dumps(analysis, indent=4))

    if args.output:
        export_iocs(analysis, args.output)

if __name__ == "__main__":
    main()
