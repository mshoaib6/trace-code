import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt

def map_source(foldername):
    if 'exploitdb' in foldername:
        return 'EDB'
    elif 'kernelhub' in foldername:
        return 'KernelHub'
    elif 'rhinoseclab' in foldername:
        return 'RhinoSecLabs'
    elif 'poc-in-gh' in foldername:
        return 'PoCInGitHub'
    else:
        return None

def compute_overlap():
    df = pd.read_pickle("total_results.pkl")
    df['Source'] = df['Foldername'].apply(map_source)
    df = df.groupby('Source').apply(lambda x: x.drop_duplicates(subset='CVE ID')).reset_index(drop=True)
    sources = ['EDB', 'KernelHub', 'RhinoSecLabs', 'PoCInGitHub']
    overlap_df = pd.DataFrame(columns = sources, index=sources)

    for source1 in sources:
        for source2 in sources:
            if source1 == source2:
                overlap = 0
            else:
                CVEIDs1 = set(df[df['Source'] == source1]['CVE ID'])
                CVEIDs2 = set(df[df['Source'] == source2]['CVE ID'])
                overlap = len(CVEIDs1.intersection(CVEIDs2))
            overlap_df.loc[source1][source2] = overlap

    overlap_df = overlap_df.apply(pd.to_numeric)
    print(overlap_df)
    sns.heatmap(overlap_df, cmap='Blues', annot=True, fmt='g')
    plt.xlabel("Source")
    plt.ylabel("Source")
    plt.savefig("figures/source_cve_overlap.pdf")

if __name__ == "__main__":
    compute_overlap()