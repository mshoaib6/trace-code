import pandas as pd


def add_scores():
    df_pocs = pd.read_csv("total_results.csv")
    df_cves = pd.read_csv("cves.csv")

    df_merged = df_pocs.merge(df_cves[["CVE ID", "Publish Date", "Score"]],
                            on="CVE ID",
                            how="left")

    df_merged.to_csv("total_results_with_scores.csv", index=False)
    df_merged.to_pickle("total_results_with_scores.pkl")

    print(df_merged.head())

if __name__ == "__main__":
    add_scores()