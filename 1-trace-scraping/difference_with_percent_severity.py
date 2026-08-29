import pandas as pd
import matplotlib.pyplot as plt
import numpy as np

def compute_differences():
    df = pd.read_pickle("total_results.pkl")

    df['CVE-Date'] = pd.to_datetime(df['Publish Date'], format="mixed", errors="raise")
    df['POC-Date'] = pd.to_datetime(df['Date'], format="mixed", errors="raise", utc=True).dt.tz_convert(None)
    dates = (df['POC-Date'] - df['CVE-Date']).dt.days
    df['Difference'] = dates
    df['Score'] = df['Score'].astype('float')

    low_severity = df[(df['Score'] >= 0) & (df['Score'] <= 3)]
    medium_severity = df[(df['Score'] > 3) & (df['Score'] <= 6)]
    high_severity = df[(df['Score'] > 6) & (df['Score'] <= 10)]

    low_count = len(low_severity)
    medium_count = len(medium_severity)
    high_count = len(high_severity)

    total_count = len(df)

    low_percentage = (low_count / total_count) * 100
    medium_percentage = (medium_count / total_count) * 100
    high_percentage = (high_count / total_count) * 100

    print(f"Low Severity PoCs: {low_count} ({low_percentage:.2f}%)")
    print(f"Medium Severity PoCs: {medium_count} ({medium_percentage:.2f}%)")
    print(f"High Severity PoCs: {high_count} ({high_percentage:.2f}%)")

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
    plt.ylabel(f'Difference between CVE Publish Date and PoC publish date')
    plt.savefig('figures/filtered_differences.pdf')
    plt.clf()

    filtered_difference_groups = filtered.groupby('CVE-Year')['Difference']
    print("Filtered Mean: ", filtered_difference_groups.mean())
    print("Filtered Median: ", filtered_difference_groups.median())
    print("Filtered Std Deviation: ", filtered_difference_groups.std())

if __name__ == "__main__":
    compute_differences()