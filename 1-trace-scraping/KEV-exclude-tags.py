import pandas as pd

def count_pocs_for_cves():
    known_exploited_vulnerabilities_path = "known_exploited_vulnerabilities.csv"
    known_exploited_vulnerabilities_df = pd.read_csv(known_exploited_vulnerabilities_path)

    total_results_path = "total_results.pkl"
    total_results_df = pd.read_pickle(total_results_path)

    total_results_df['CVE ID'] = total_results_df['CVE ID'].astype(str)
    known_exploited_vulnerabilities_df['CVE ID'] = known_exploited_vulnerabilities_df['cveID'].astype(str)
    filtered_known_exploited = known_exploited_vulnerabilities_df[
        known_exploited_vulnerabilities_df['CVE ID'].str.match(r'CVE-201[8-9]|CVE-202[0-2]')
    ]

    exclude_tags = [
        "ipad", "watchos", "android", "gpu", "chipsets",
        "snapdragon", "directx", "nas", "routers", "flash", "tar",
        "mobileiron", "helpdesk", "roundcube", "mobile devices",
        "backup exec", "sureline", "backup replication", "collaboration",
        "vsa", "pixel", "drupal", "media", "multiple products", "gateway",
        "device", "router", "os", "firmware", "kernel", "control system", 
        "engine", "dir", "sdk", "serv", "infrastructure", "provider"
    ]
    pattern = '|'.join(exclude_tags)
    filtered_known_exploited = filtered_known_exploited[
        ~filtered_known_exploited['product'].str.contains(pattern, case=False, na=False)
    ]

    results = {}
    for year in range(2018, 2023):
        year_str = str(year)
        year_known_exploited = filtered_known_exploited[
            filtered_known_exploited['CVE ID'].str.startswith(f'CVE-{year_str}')
        ]
        total_year_known = len(year_known_exploited)

        year_in_total_results = total_results_df[
            total_results_df['CVE ID'].str.startswith(f'CVE-{year_str}')
        ]
        matched_cves = year_known_exploited[
            year_known_exploited['CVE ID'].isin(year_in_total_results['CVE ID'])
        ]
        matched_count = len(matched_cves)

        percentage_matched = (matched_count / total_year_known) * 100 if total_year_known > 0 else 0
        results[year_str] = {
            'total_known': total_year_known,
            'matched': matched_count,
            'percentage': percentage_matched
        }

        unmatched_cves = year_known_exploited[~year_known_exploited['CVE ID'].isin(year_in_total_results['CVE ID'])]
        results[year_str]['unmatched_products'] = unmatched_cves['product'].tolist()

    for year, data in results.items():
        print(f"Year: {year}")
        print(f"Total Known Exploited CVEs: {data['total_known']}")
        print(f"Matched CVEs in Total Results: {data['matched']}")
        print(f"Percentage Matched: {data['percentage']:.2f}%")
        print(f"Unmatched Products: {data['unmatched_products']}")
        print("\n")

if __name__ == "__main__":
    count_pocs_for_cves()