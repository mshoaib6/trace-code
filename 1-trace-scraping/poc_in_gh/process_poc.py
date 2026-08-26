import os
from pandas import read_csv, DataFrame
import json
from git import Repo
import git
import shutil
from tqdm import tqdm
import time
import gc


from config import START_YEAR


def clone_repo(url, poc_id):
    repo = Repo.clone_from(url, f"total_folder/poc-in-gh/{poc_id}", depth=1)
    repo.close()
    time.sleep(1)


def scrape_from_poc():
    print("Scraping from PoC in GitHub...")

    clone_path = os.path.abspath(os.path.join(os.path.dirname(__file__), 'PoC-in-GitHub'))
    if not os.path.isdir(clone_path):
        print("PoC-in-GitHub not found, cloning Repo...", flush=True)  
        url = "git@github.com:nomi-sec/PoC-in-GitHub.git"
        repo = Repo.clone_from(url, clone_path)
        repo.close()
          
    directories = os.listdir('poc_in_gh/PoC-in-GitHub')
    directories.sort()
    directories = [dir for dir in directories if dir.isdigit() and int(dir) >= START_YEAR]

    #load cve info from csv
    cve_data = read_csv(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'cves.csv')))
    cve_column_names = cve_data.columns.to_list()

    #load prior scraped data, if available
    if os.path.exists("poc_in_gh/poc-in-gh-results.csv"):
        df = read_csv("poc_in_gh/poc-in-gh-results.csv")
    else:
        df = DataFrame(columns=['POC ID', 'CVE ID','CVE-Year','Foldername','Date','github-updated-at','github-pushed-at'])
    
    #pocs are saved in total_folder/poc-in-gh
    save_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../total_folder/poc-in-gh'))
    for dir in tqdm(directories):
        if not os.path.isdir('poc_in_gh/PoC-in-GitHub/' + dir):
            continue
        files = os.listdir('poc_in_gh/PoC-in-GitHub/' + dir)
        files.sort()
        for file in files:
            try:
                with open('poc_in_gh/PoC-in-GitHub/' + dir + '/' + file) as f:
                    data = json.load(f)
                    cve = file.split('.')[0]
                    matching_rows = cve_data[cve_data['CVE ID'] == cve]
                    if len(matching_rows) == 1:
                        for entry in data:
                            poc_id = entry['id']
                            if 'POC ID' in df.columns and df['POC ID'].eq(poc_id).any():
                                print("This POC has been saved already, skipping")
                                continue
                            folder_path = f"poc-in-gh/{poc_id}"
                            if not os.path.exists(folder_path):
                                url = entry['html_url']
                                                
                                # Convert to ssh url
                                before, sep, after = url.partition("github.com/")
                                if not sep: #partition failed
                                    continue
                                                                        
                                # Ensure trailing ".git"
                                if not after.endswith(".git"):
                                    after += ".git"
                                                                     
                                # Combine into SSH form
                                ssh_url = f"git@github.com:{after}"
                                clone_repo(ssh_url, poc_id)

                            new_row = {
                                "POC ID": poc_id,
                                "CVE ID": cve,
                                "Foldername": folder_path,
                                "CVE-Year": dir,
                                "Date": entry["created_at"],
                                "github-updated-at": entry["updated_at"],
                                "github-pushed-at": entry["pushed_at"],
                            }
                            df.loc[len(df)] = new_row  # adds a new row to the end of the df in memory

                            #append this one line to the csv file
                            row_df = DataFrame([new_row])
                            file_path = "poc_in_gh/poc-in-gh-results.csv"
                            file_exists = os.path.exists(file_path) and os.path.getsize(file_path) > 0
                            with open(file_path, "a") as f:
                                row_df.to_csv(f, index=False, header=not file_exists)

                    else:
                        print('missing CVE data for ' + cve)
            except git.exc.GitCommandError as e:
                print("ERROR:", e)
                continue

    df.to_pickle("poc_in_gh/poc-in-gh-results.pkl")
    print("Done scraping from PoC in GitHub!")

if __name__ == "__main__":
    scrape_from_poc()
