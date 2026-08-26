from scrape_cves.nvd_scrape import cve_scrape
from exploit_db.edb_main import scrape_from_edb
from kernelhub.kernelhub_scraper import scrape_from_kernelhub
from poc_in_gh.process_poc import scrape_from_poc
from rhinoseclab.rhino_extract import scrape_from_rhino
from concat_dataframes import concat_dataframes
from copy_tags import copy_tags
from boxplots import generate_boxplots
from compute_stats import compute_stats
from heatmaps import generate_heatmaps
from compute_cve_information import compute_cve_information
from compute_source_cve_overlap import compute_overlap
from cve_count_statistics import count_statistics
from date_differences import compute_differences


def main():

    cve_scrape()
    scrape_from_edb()
    scrape_from_kernelhub()
    scrape_from_poc()
    scrape_from_rhino()
    
    concat_dataframes()
    copy_tags()
    generate_boxplots()
    generate_heatmaps()
    compute_cve_information()
    compute_stats()
    compute_overlap()
    count_statistics()
    compute_differences()
    

if __name__ == "__main__":
    main()
