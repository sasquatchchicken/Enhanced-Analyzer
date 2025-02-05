# Enhanced-Analyzer

This python script decodes Base64-encoded data, extracts embedded IP addresses, domains, URLs, and artifacts, performs hash analysis, and queries threat intelligence databases to detect malware, phishing, or suspicious activity. This Base64 Analyzer is designed for Digital Forensics & Incident Response (DFIR) and Threat Intelligence Analysis. It integrates AI-based classification to differentiate between malware, encryption keys, and legitimate files.

**Base64 Decoding: Converts encoded data back to raw format for analysis.**

**Entropy Analysis: Detects whether data is likely hashed, encrypted, or plaintext.**

**IOC Extraction: Extracts IPs, domains, and URLs from decoded data.**

**Hash Lookup: Queries VirusTotal, IBM X-Force, AbuseIPDB, AlienVault, and Shodan for known malware hashes or malicious indicators.**

**AI-Based Classification: Uses a machine learning model to predict if a hash represents malware, an encryption key, or a benign file.**

**SIEM Integration: Saves findings to a JSON report for further investigation.**

## Instal Dpendencies
  ```
  pip install requests
  pip install joblib
  pip install scikit-learn
  pip install python-magic
  ```

## Sign up for API Keys
Once you have the API keys edit the script and replace placeholders
  ```
API_KEYS = {
    "virustotal": "YOUR_VIRUSTOTAL_KEY",  
    "abuseipdb": "YOUR_ABUSEIPDB_KEY",
    "alienvault": "YOUR_ALIENVAULT_KEY",
    "ibmxforce": "YOUR_XFORCE_KEY",
    "shodan": "YOUR_SHODAN_KEY"
}
  ```

## USAGE
Analyze base64 encoding string
  ```
python enhancedAnalyzer.py -i <"insert_base64_string_here"> 
  ```
Analyze a file containing base64 data
  ```
python enhancedAnalyzer.py -f <insert_file_here>
  ```
Export results to JSON
  ```
python enhancedAnalyzer.py -i <"insert_base64_string_here"> -o output.json
  ```
## Use Cases
Digital Forensics (DFIR):
Identify malware samples, stolen credentials, or obfuscated attack payloads.

Threat Intelligence Analysts:
Correlate malicious hashes, IPs, and domains with threat intelligence feeds.

Incident Response Teams:
Detect steganography, data exfiltration, or C2 (Command & Control) communications hidden in Base64.

SOC Analysts / SIEM Integration:
Use with Splunk, Elastic Security, or QRadar to automate hash lookups & threat detection.

Reverse Engineers / Malware Analysts:
Extract obfuscated payloads, embedded shellcode, or encryption keys from suspicious files.

***before running the script you must first run the train_hash_model.py file and have the output file stored in the same directory as the enhancedAnalyzer.py file***
  ```
python train_hash_model.py
output = hash_model.pkl
  ```
## API rate limits apply. Rotate keys when necessary.
