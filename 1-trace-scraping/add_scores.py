import pandas as pd



def add_scores():
    # --- Load your existing data ---
    # df_pocs: your dataframe containing PoC metadata
    # df_cves: dataframe loaded from your CSV containing CVE scores and dates
    df_pocs = pd.read_csv("total_results.csv")         # Replace with your file
    df_cves = pd.read_csv("cves.csv")   # Contains: CVE ID, Date, Year, Base Score

    # --- Merge: left join so every PoC stays, even if CVE score is missing ---
    df_merged = df_pocs.merge(df_cves[["CVE ID", "Publish Date", "Score"]],
                            on="CVE ID",
                            how="left")

    # --- Save result ---
    df_merged.to_csv("total_results_with_scores.csv", index=False)
    df_merged.to_pickle("total_results_with_scores.pkl")

    print(df_merged.head())

if __name__ == "__main__":
    add_scores()