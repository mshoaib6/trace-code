import matplotlib.pyplot as plt
from pandas import read_pickle

def generate_boxplots():
    total_df = read_pickle("total_results.pkl")
    countdf = total_df.groupby(['CVE ID', 'CVE-Year']).size().reset_index(name='Count')

    ax = countdf.boxplot(column='Count', by='CVE-Year')
    plt.xlabel('CVE Year')
    plt.ylabel('Count')
    plt.title('POCs per CVE grouped by Year')
    ax.set_xticklabels(ax.get_xticklabels(), rotation=45)
    ax.set_title('')
    plt.yscale("log")

    plt.savefig('figures/boxplot.pdf')
    plt.clf()

    year_counts = countdf['CVE-Year'].value_counts().sort_index()

    plt.bar(year_counts.index, year_counts.values)

    plt.xlabel('CVE Year')
    plt.ylabel('Count')
    plt.title('PoCs per CVE-Year')

    plt.xticks(rotation=45)

    plt.savefig('figures/bargraph.pdf')

if __name__ == "__main__":
    generate_boxplots()