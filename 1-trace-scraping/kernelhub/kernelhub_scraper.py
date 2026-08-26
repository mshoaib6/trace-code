import os
import shutil
import re
from pandas import DataFrame, read_csv
import git

from config import START_YEAR


def extract_section_from_markdown(markdown_text, section_title):
    pattern = r"#+\s*" + re.escape(section_title) + r"\s*\n(.*?)(?=\n#+|\Z)"
    match = re.search(pattern, markdown_text, re.IGNORECASE | re.DOTALL)

    if match:
        return match.group(1).strip()
    else:
        return None

def get_folder_creation_date(folder_path):
    repo = git.Repo(os.path.abspath(os.path.join(os.path.dirname(__file__), 'Kernelhub')))
    folder_creation_commit = repo.git.log('--reverse', '--format=%H', folder_path).splitlines()[-1]
    folder_creation_date = repo.git.show('-s', '--format=%ci', folder_creation_commit).strip().split()[0]
    return folder_creation_date

def get_folder_update_date(folder_path):
    repo = git.Repo(os.path.abspath(os.path.join(os.path.dirname(__file__), 'Kernelhub')))
    folder_update_date = repo.git.log('-1', '--format=%ci', folder_path).strip().split()[0]
    return folder_update_date

def scrape_from_kernelhub():
    if os.path.isfile('kernelhub/kernelhub_results.pkl'):
        print("Kernelhub already scraped")
        return
    
    clone_path = os.path.abspath(os.path.join(os.path.dirname(__file__), 'Kernelhub'))
    # need repo with PoCs, clone if does not exist
    if not os.path.isdir(clone_path):
        print("KernelHub clone not found, cloning the git repo...", flush=True)
        kh_url = "https://github.com/Ascotbe/Kernelhub.git"
        print(f"clone_path: {clone_path}")
        git.Repo.clone_from(kh_url, clone_path)


    foldername = os.path.join(clone_path, "Windows")
    index = 0
    files = os.listdir(foldername)
    files = [file for file in files if 'CVE' in file and int(file.split('-')[1]) >= START_YEAR]
    cve_data = read_csv(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'cves.csv')))
    cve_column_names = cve_data.columns.to_list()
    df = DataFrame()
    print("Scraping from Kernelhub...")
    for dir in files:
        filename = re.sub(r"[-‑]", "-", dir)
        cves = filename.split("_")
        for cve in cves:
            matching_rows = cve_data[cve_data['CVE ID'] == cve]
            if len(matching_rows) == 0:
                print("no match found")
            else:
                total_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../total_folder'))
                folder_path = f"{total_path}/kernelhub/kernelhub-{index}"
                if not os.path.exists(folder_path):
                    os.makedirs(folder_path)
                    inner_files = os.listdir(f"{foldername}/{dir}")
                    list = (file for file in inner_files if filename in re.sub(r"[-‑]", "-", file))
                    file = next(list, None)
                    if not file:
                        with open(f"{folder_path}/filename.txt", "w") as f1:
                            with open(f"{foldername}/{dir}/README.md", "r") as f2:
                                f1.write(extract_section_from_markdown(f2.read(), "利用方式"))
                    else:
                        shutil.copytree(f"{foldername}/{dir}", f"{folder_path}/{dir}")
                output_filename = f"kernelhub/kernelhub-{index}"
                df.loc[index, cve_column_names] = matching_rows.iloc[0]
                df.loc[index, 'Foldername'] = output_filename
                df.loc[index, 'CVE-Year'] = cve.split('-')[1]
                df.loc[index, 'Date'] = get_folder_creation_date('Windows/' + dir)
                df.loc[index, 'github-updated-at'] = get_folder_update_date('Windows/' + dir)
                index += 1

    df.to_csv('kernelhub/kernelhub_results.csv')
    df.to_pickle('kernelhub/kernelhub_results.pkl')

    print("Finished scraping from Kernelhub!")