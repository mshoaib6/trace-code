import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
from add_scores import add_scores


def compute_differences():

    add_scores()

    df = pd.read_pickle("total_results_with_scores.pkl")

    df['CVE-Date'] = pd.to_datetime(df['Publish Date'], format="mixed", errors="raise")
    df['POC-Date'] = pd.to_datetime(df['Date'], format="mixed", errors="raise", utc=True).dt.tz_convert(None)
    dates = (df['POC-Date'] - df['CVE-Date']).dt.days
    df['Difference'] = dates
    df['Score'] = df['Score'].astype('float')

    df = df.dropna(subset=['Score'])

    ax = df.plot.scatter(x='Score', y='Difference')
    x = df['Score']
    y = df['Difference']
    b, a = np.polyfit(x, y, deg=1)
    xseq = np.linspace(0, 10, num=2)
    ax.plot(xseq, a + b * xseq, color='r', lw=2.5)

    plt.xlabel('Score (Severity)')
    plt.ylabel('Difference between CVE Publish Date and PoC publish date')
    plt.savefig('figures/difference-score-scatter.pdf')
    plt.clf()

    df = df[df['Difference'] >= 0]
    df = df[df['Difference'] <= 365]

    df_sorted = df.sort_values('Difference')
    df_unique = df_sorted.drop_duplicates('CVE ID', keep='first')
    df = df_unique.reset_index(drop=True)
    dates = df['Difference']

    ax = df.plot.scatter(x='Score', y='Difference')
    x = df['Score']
    y = df['Difference']
    b, a = np.polyfit(x, y, deg=1)
    xseq = np.linspace(0, 10, num=2)
    ax.plot(xseq, a + b * xseq, color='r', lw=2.5)

    plt.xlabel('Score (Severity)')
    plt.ylabel('Difference between CVE Publish Date and PoC publish date')
    plt.savefig('figures/difference-score-scatter-multiple-entries-removed-only-positive-less-than-one-year.pdf')
    plt.clf()

    print("Mean: ", dates.mean())
    print("Median: ", dates.median())
    print("Min: ", dates.min())
    print("Max: ", dates.max())
    print("Standard Deviation: ", dates.std())

    ax = df.boxplot(column='Difference', by='CVE-Year')
    plt.xlabel('CVE Year')
    plt.ylabel('Difference between CVE Publish Date and PoC publish date')
    plt.savefig('figures/differences.pdf')
    plt.clf()

    difference_groups = df.groupby('CVE-Year')['Difference']
    print("Mean: ", difference_groups.mean())
    print("Median: ", difference_groups.median())
    print("Std Deviation: ", difference_groups.std())

    score_limit = 8
    filtered = df[df['Score'] >= score_limit]
    filtered_dates = filtered['Difference']

    print("Filtered Mean: ", filtered_dates.mean())
    print("Filtered Median: ", filtered_dates.median())
    print("Filtered Min: ", filtered_dates.min())
    print("Filtered Max: ", filtered_dates.max())
    print("Filtered Standard Deviation: ", filtered_dates.std())

    ax = filtered.boxplot(column='Difference', by='CVE-Year')
    plt.xlabel('CVE Year')
    plt.savefig('figures/filtered_differences.pdf')
    plt.clf()

    filtered_difference_groups = filtered.groupby('CVE-Year')['Difference']
    print("Filtered Mean: ", filtered_difference_groups.mean())
    print("Filtered Median: ", filtered_difference_groups.median())
    print("Filtered Std Deviation: ", filtered_difference_groups.std())

if __name__ == "__main__":
    compute_differences()