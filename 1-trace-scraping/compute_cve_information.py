from pandas import read_pickle, read_csv
import pandas as pd

def compute_cve_information():
    cves = read_csv('cves.csv')
    df = read_pickle('total_results.pkl')

    counts_unique = df.groupby('CVE-Year')['CVE ID'].nunique()
    counts = df['CVE-Year'].value_counts()

    print("#CVEs")
    print(counts_unique)

    print("#POCs")
    print(counts)

    df_unique = df.drop_duplicates(subset=['CVE ID'])
    cves_unique = cves.drop_duplicates(subset=['CVE ID'])
    cves_unique['CVE-Year'] = cves_unique['CVE ID'].str.split("-", expand=True)[1]
    cves_unique['CVE-Year'] = cves_unique['CVE-Year'].astype(int)
    cves_unique = cves_unique[cves_unique['CVE-Year'] >= 2018]

    proportions = cves_unique.groupby('CVE-Year').apply(lambda x: x['CVE ID'].isin(df_unique['CVE ID']).mean())

    print(proportions)

    totals = pd.DataFrame()
    totals.loc[0, 'Unique CVEs targeted'] = df['CVE ID'].nunique()
    totals.loc[0, '% CVEs assigned by NVD'] = cves_unique['CVE ID'].isin(df_unique['CVE ID']).mean()
    totals.loc[0, '# PoCs'] = len(df)

    print("Totals")
    print(totals)

if __name__ == "__main__":
    compute_cve_information()