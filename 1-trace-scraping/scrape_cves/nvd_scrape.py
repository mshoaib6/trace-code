# %%
# Scrape CVEs (just ids and years) for last 5 years from NVD database

import requests
from bs4 import BeautifulSoup
from tqdm import tqdm
import pandas as pd
import os
from datetime import datetime, timedelta

#URL to NVD's CVE database
BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0/"
API_KEY = os.environ.get("NVD_API_KEY", "")
START_YEAR = 2019
END_YEAR = 2026 #exclusive


def get_any_cvss_score(cve):
    metrics = cve.get("metrics", {})

    # Priority: V4 → V3.1 → V3.0 → V2
    for key in ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        if key in metrics and len(metrics[key]) > 0:
            entry = metrics[key][0]
            data = entry["cvssData"]
            return data.get("baseScore")

    return None


def fetch_cves(start_date, end_date):
    """
    Fetch CVEs between two datetimes (ISO8601 with ms).
    """
    headers = {
    "apiKey": API_KEY
    }
    params = {
        "pubStartDate": start_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate": end_date.strftime("%Y-%m-%dT%H:%M:%S.999"),
        "resultsPerPage": 2000
    }
    all_cves = []
    start_index = 0
    
    while True:
        params["startIndex"] = start_index
        resp = requests.get(BASE_URL, headers=headers, params=params)
        resp.raise_for_status()
        data = resp.json()
        
        results = data.get("vulnerabilities", [])
        if not results:
            break
        
        for result in results:
            cve_id = result["cve"]["id"]
            published = result["cve"]["published"]
            year = published[:4]
            score = get_any_cvss_score(result["cve"])
            if not score:
                print(f"Could not find any score for this CVE")
            else:
                print(f"Score found: {score}")
            all_cves.append((cve_id, year, published, score))
        
        start_index += len(results)
        if start_index >= data["totalResults"]:
            break
    
    return all_cves


def fetch_year(year):
    """
    Fetch CVEs for an entire year by chunking into <=120 day ranges.
    """
    results = []
    start = datetime(year, 1, 1)
    end = datetime(year + 1, 1, 1)

    chunk = timedelta(days=100)
    cur = start
    while cur < end:
        nxt = min(cur + chunk, end)
        results.extend(fetch_cves(cur, nxt))
        cur = nxt
    return results


def cve_scrape():

    filepath = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'cves.csv'))

    if os.path.isfile(filepath) and os.path.getsize(filepath) > 1000:  # adjust threshold if needed
        print("CVE data already collected, moving on...")
        return
    
    print("CSV looks empty or header-only, repopulating...", flush=True)

    all_cves = []
    for year in range(START_YEAR, END_YEAR):
        print(f"Fetching {year}...")
        yearly_cves = fetch_year(year)
        all_cves.extend(yearly_cves)

    df = pd.DataFrame(all_cves, columns=["CVE ID", "CVE-Year", "Publish Date", "Score"])
    df.to_csv(filepath, index=False)
    print(f"Saved {len(df)} CVEs to cves.csv")


if __name__ == "__main__":
    cve_scrape()
