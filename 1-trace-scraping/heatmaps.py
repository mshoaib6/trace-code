import seaborn as sns
import pandas as pd
import matplotlib.pyplot as plt

def generate_heatmaps():
    print("Generating heatmaps...")
    df = pd.read_pickle('total_results.pkl')

    pivot_df = pd.pivot_table(df, values='CVE ID', index='CVE-Year', columns='Publish-Year', aggfunc='count')

    plt.figure(figsize=(10, 8))
    ax = sns.heatmap(pivot_df, cmap='Blues', annot=True, cbar=False, fmt='g')
    plt.title('CVE Year vs. Repository Creation Date')
    plt.xlabel('Date of Repository Creation')
    plt.ylabel('CVE Year')

    plt.savefig('figures/CVE-Year-Date-heatmap.pdf')
    plt.clf()

    pivot_df = pd.pivot_table(df, values='CVE ID', index='CVE-Year', columns='github-updated-at', aggfunc='count')

    plt.figure(figsize=(10, 8))
    ax = sns.heatmap(pivot_df, cmap='Blues', annot=True, cbar=False, fmt='g')
    plt.title('CVE Year vs. Last Repository Update Date')
    plt.xlabel('Date of Last Repository Update')
    plt.ylabel('CVE Year')

    plt.savefig('figures/CVE-Year-updated-date-heatmap.pdf')
    plt.clf()

    print("Finished generating heatmaps!")

if __name__ == "__main__":
    generate_heatmaps()