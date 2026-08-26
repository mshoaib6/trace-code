import requests
from bs4 import BeautifulSoup
import pandas as pd
import concurrent.futures
import csv
import time

def fetch_snort_rules(cve):
    base_url = "https://www.snort.org/search"
    search_url = f"{base_url}?utf8=✓&q={cve}&submit_search="
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'}
    try:
        response = requests.get(search_url, headers=headers)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            links = soup.find_all('a', href=True)
            rule_links = [link['href'] for link in links if '/rule_docs/' in link['href'] or '/advisories/' in link['href']]
            return (cve, ', '.join(rule_links)) if rule_links else (cve, None)
        elif response.status_code == 429:
            print("Rate limited. Sleeping for 5 seconds.")
            time.sleep(5)  # Reduced sleep time to 5 seconds
            return fetch_snort_rules(cve)
    except requests.RequestException as e:
        print(f"Error fetching {cve}: {e}")
        return (cve, None)

def save_results(results):
    with open('snort_rules.csv', 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['CVE', 'Rule Links'])
        for result in results:
            if result[1]:
                writer.writerow(result)

def main():
    cve_data = pd.read_csv('cves.csv')
    cves = cve_data['CVE ID'].tolist()
    results = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = {executor.submit(fetch_snort_rules, cve): cve for cve in cves}
        count = 0
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            results.append(result)
            count += 1
            if count % 100 == 0:
                print(f"Processed {count} rules.")
    
    save_results(results)
    print("Completed processing. Results saved in snort_rules.csv.")

if __name__ == "__main__":
    main()
