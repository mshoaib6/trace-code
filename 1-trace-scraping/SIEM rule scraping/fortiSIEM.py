import requests
from bs4 import BeautifulSoup
import pandas as pd
import re
import concurrent.futures
import time

def load_cves(file_path):
    cve_data = pd.read_csv(file_path)
    return set(cve_data['CVE ID'])

def fetch_and_parse_html_for_links(url):
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    rule_links = []
    base_url = "https://help.fortinet.com/fsiem/Public_Resource_Access/7_2_2/rules/"
    for link in soup.find_all('a', href=True):
        if link['href'].endswith('.htm'):
            full_url = base_url + link['href']
            rule_links.append(full_url)
    return rule_links

def fetch_cve_from_link(link, known_cves):
    try:
        response = requests.get(link, timeout=10)
        if response.status_code == 200:
            page_cves = set(re.findall(r"CVE-\d{4}-\d+", response.text))
            relevant_cves = page_cves.intersection(known_cves)
            if relevant_cves:
                return {link: list(relevant_cves)}
    except requests.RequestException:
        return {link: 'Failed to fetch'}
    return {link: []}

def main():
    file_path = 'cves.csv'
    url = 'https://help.fortinet.com/fsiem/Public_Resource_Access/7_2_2/rules/rule_descriptions.htm'
    known_cves = load_cves(file_path)
    rule_links = fetch_and_parse_html_for_links(url)
    
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        futures = [executor.submit(fetch_cve_from_link, link, known_cves) for link in rule_links]
        for future in concurrent.futures.as_completed(futures):
            results.append(future.result())
            if len(results) % 100 == 0:
                print(f"Processed {len(results)} links")
    
    # Flatten the results and filter out empty entries
    flat_results = {k: v for d in results for k, v in d.items() if v}
    df = pd.DataFrame(list(flat_results.items()), columns=['Rule URL', 'CVEs'])
    df.to_csv('forti_rules.csv', index=False)
    print("CSV file created with found CVEs and their corresponding rule URLs.")

if __name__ == "__main__":
    main()
