import requests
from bs4 import BeautifulSoup

def get_forms(url):
    try:
        soup = BeautifulSoup(requests.get(url, timeout=10).text, "html.parser")
        return soup.find_all("form")
    except Exception as e:
        print(f"[!] Failed to fetch forms from {url}: {e}")
        return []

def form_details(form):
    details = {}
    try:
        action = form.attrs.get("action").lower() if form.attrs.get("action") else ""
        method = form.attrs.get("method", "get").lower()
        inputs = []
        for input_tag in form.find_all("input"):
            input_type = input_tag.attrs.get("type", "text")
            input_name = input_tag.attrs.get("name")
            if input_name:
                inputs.append({"type": input_type, "name": input_name})
        details["action"] = action
        details["method"] = method
        details["inputs"] = inputs
    except Exception as e:
        print(f"[!] Failed to parse form details: {e}")
    return details

def submit_form(form_details, url, payload):
    target_url = urljoin(url, form_details["action"])
    data = {}
    for input in form_details["inputs"]:
        data[input["name"]] = payload
    try:
        if form_details["method"] == "post":
            return requests.post(target_url, data=data, timeout=10)
        else:
            return requests.get(target_url, params=data, timeout=10)
    except Exception as e:
        print(f"[!] Failed to submit form to {target_url}: {e}")
        return None

def is_vulnerable(response):
    errors = ["you have an error in your sql syntax", "warning: mysql", "unclosed quotation mark", "quoted string not properly terminated"]
    return any(error in response.text.lower() for error in errors)

def scan(url, payloads):
    print(f"[+] Scanning {url} for SQL Injection")
    forms = get_forms(url)
    print(f"[+] Detected {len(forms)} form(s) on {url}")
    results = []
    for form in forms:
        form_info = form_details(form)
        for payload in payloads:
            res = submit_form(form_info, url, payload)
            if res and is_vulnerable(res):
                print(f"[!!] Possible vuln: {urljoin(url, form_info['action'])} | payload: {payload.strip()}")
                results.append(f"[!!] Possible vuln: {urljoin(url, form_info['action'])} | payload: {payload.strip()}")
    return results

from urllib.parse import urljoin

if __name__ == "__main__":
    url = input("Enter target URL (with http/https): ").strip()
    try:
        with open("payloads.txt", "r") as f:
            payloads = f.readlines()
    except FileNotFoundError:
        print("[!] payloads.txt not found.")
        exit(1)
    findings = scan(url, payloads)
    with open("sqli_results.txt", "w") as out:
        out.write("\n".join(findings))
    print("[+] Scan completed. Results saved to sqli_results.txt")
