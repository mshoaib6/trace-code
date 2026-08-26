from pandas import read_pickle, concat, read_csv
import numpy as np
import pandas as pd

def concat_dataframes():
    df1 = read_pickle("exploit_db/exploitdb-results.pkl")
    df2 = read_pickle("kernelhub/kernelhub_results.pkl")
    df3 = read_pickle("rhinoseclab/rhino_results.pkl")
    df4 = read_pickle("poc_in_gh/poc-in-gh-results.pkl")

    total_df = concat([df1, df2, df3, df4], ignore_index=True)
    
    # strip whitespace and other non-numeric characters
    total_df['CVE-Year'] = total_df['CVE-Year'].astype(str).str.replace(r'\D', '', regex=True)
    total_df['CVE-Year'] = pd.to_numeric(total_df['CVE-Year'], errors='coerce').astype('Int64')
    total_df = total_df[total_df['CVE-Year'] >= 2018]
    print(total_df['CVE-Year'].value_counts())
    total_df.loc[total_df['Foldername'].str.contains('edb'), 'github-updated-at'] = total_df['Date']
    total_df['Publish-Year'] = total_df['Date'].str.split('-', expand=True)[0]
    total_df['github-updated-at'] = total_df['github-updated-at'].str.split('-', expand=True)[0]
    print("EDB: " + str(len(total_df[total_df['Foldername'].str.contains("exploitdb")])))
    print("rhinoseclab: " + str(len(total_df[total_df['Foldername'].str.contains("rhinoseclab")])))
    print("poc-in-gh: " + str(len(total_df[total_df['Foldername'].str.contains("poc-in-gh")])))
    print("kernelhub: " + str(len(total_df[total_df['Foldername'].str.contains("kernelhub")])))
    total_df['Publish-Year'] = total_df['Publish-Year'].astype(int)
    print(total_df[total_df['CVE-Year'] > total_df['Publish-Year']])

    # Make 'Tags' column with empty lists (this column not scraped as of 2025)
    total_df['Tags'] = total_df.get('Tags', pd.Series([[]] * len(total_df)))

    total_df = total_df.reset_index()

    total_df.to_pickle("total_results.pkl")
    total_df.to_csv("total_results.csv") 

if __name__ == "__main__":
    concat_dataframes()
