import os
import shutil
import re
import git
from pandas import DataFrame, read_csv

from config import START_YEAR


def extract_section_from_markdown(markdown_text, section_title):
    pattern = r"#+\s*" + re.escape(section_title) + r"\s*\n(.*?)(?=\n#+|\Z)"
    match = re.search(pattern, markdown_text, re.IGNORECASE | re.DOTALL)

    if match:
        return match.group(1).strip()
    else:
        return None

def get_folder_creation_date(folder_path):
    repo = git.Repo("rhinoseclab/CVEs")
    folder_creation_commit = repo.git.log('--reverse', '--format=%H', '--', folder_path).splitlines()[-1]
    folder_creation_date = repo.git.show('-s', '--format=%ci', folder_creation_commit).strip().split()[0]
    return folder_creation_date

def get_folder_update_date(folder_path):
    repo = git.Repo("rhinoseclab/CVEs")
    folder_update_date = repo.git.log('-1', '--format=%ci', folder_path).strip().split()[0]
    return folder_update_date

def scrape_from_rhino():
    print("Scraping from Rhino Security Labs...")

    clone_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'rhinoseclab/CVEs'))
    if not os.path.isdir(clone_path):
        print("Rhinoseclab CVEs not found, cloning from the git repo...", flush=True)
        rsl_url = "https://github.com/RhinoSecurityLabs/CVEs.git"
        print(f"clone_path: {clone_path}")
        git.Repo.clone_from(rsl_url, clone_path)

    if not os.path.exists("total_folder/rhinoseclab"):
        os.makedirs("total_folder/rhinoseclab")

    index = 0
    files = os.listdir(clone_path)
    files = [file for file in files if 'CVE' in file and int(file.split('-')[1]) >= START_YEAR]
    cve_data = read_csv(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'cves.csv')))
    cve_column_names = cve_data.columns.to_list()
    df = DataFrame()

    for dir in files:
        cve = dir
        matching_rows = cve_data[cve_data['CVE ID'] == cve]
        if len(matching_rows) == 0:
            print("no CVE match found")
        else:
            total_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../total_folder'))
            folder_path = f"{total_path}/rhinoseclab/rhinoseclab-{index}"
            if not os.path.exists(folder_path):
                shutil.copytree(f"{clone_path}/{dir}", f"{folder_path}")
            output_filename = f"rhinoseclab/rhinoseclab-{index}"
            df.loc[index, cve_column_names] = matching_rows.iloc[0]
            df.loc[index, 'Foldername'] = output_filename
            df.loc[index, 'CVE-Year'] = cve.split('-')[1]
            df.loc[index, 'Date'] = get_folder_creation_date(dir)
            df.loc[index, 'github-updated-at'] = get_folder_update_date(dir)
            index += 1

    df.to_csv('rhinoseclab/rhino_results.csv')
    df.to_pickle('rhinoseclab/rhino_results.pkl')

    print("Finished scraping from Rhino Security Lab!")


if __name__ == "__main__":
	scrape_from_rhino()
