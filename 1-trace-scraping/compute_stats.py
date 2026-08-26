import os
from datetime import datetime
import numpy as np
import matplotlib.pyplot as plt
import pickle
import os
import seaborn as sns
import pandas as pd
import textwrap

def log(string):
    with open("log.txt", "a") as f:
        f.write(str(string) + "\n")

def handle_extension_dictionary(result, dir, path, extension):
    global total_extensions, source_extensions
    total_extensions[extension] = total_extensions.get(extension, 0) + 1
    source_extensions[path][extension] = source_extensions[path].get(extension, 0) + 1

def process_extensions(result, dir, path):
    priority = ['.c', '.py', '.rb', '.sh', '.ps1', '.js', '.cs', '.cpp', '.java', '.jar', '.pl', '.php', '.vb', '.go', '.c++', '.cc', '.m', '.as', '.msf', '.bat', '.nse', '.zip', '.tar', '.docx', '.tzt', '.cmd', '.pbxproj', '.aspx', '.conf', '.rpm', '.tgz', '.test', '.gd', '.godot', '.dat', '.exe', '.html', '.pdf', '.txt', '.json', '.yml', '.yaml', '.md', '.']
    if len(result) == 0:
        handle_extension_dictionary(result, dir, path, 'empty')
        return
    for extension in priority:
        if extension in result:
            handle_extension_dictionary(result, dir, path, extension)
            return
    for extension in result:
        if extension != '' and extension != '.':
            handle_extension_dictionary(result, dir, path, extension)
            return
    handle_extension_dictionary(result, dir, path, 'empty')
    return

def compute_stats():
    global total_extensions, source_extensions
    print("Computing stats...")

    total_results = pd.read_pickle('total_results.pkl')
    LOAD_FROM_FILE = False
    total_count = 0
    has_cve = 0

    if LOAD_FROM_FILE and (os.path.isfile('./total_extensions.pkl')):
        with open('total_extensions.pkl', 'rb') as pickle_file:
            total_extensions = pickle.load(pickle_file)
        with open('source_extensions.pkl', 'rb') as pickle_file:
            source_extensions = pickle.load(pickle_file)
    else:
        log("##########################################")
        log("Entry for: " + str(datetime.now()))

        BASE_PATH = 'total_folder/'
        folders = ['exploitdb/', 'rhinoseclab/', 'kernelhub/', 'poc-in-gh/']
        total_extensions = {}
        source_extensions = {}

        for folder in folders:
            path = BASE_PATH + folder
            files = os.listdir(path)
            source_extensions[folder] = {}

            for dir in files:
                if total_results['Foldername'].str.fullmatch(folder+dir).any():
                    total_count += 1
                    result = [os.path.splitext(f)[1] for dp, dn, filenames in os.walk(path + '/' + dir) for f in filenames]
                    process_extensions(result, dir, folder)
        
        with open('total_extensions.pkl', 'wb') as pickle_file:
            pickle.dump(total_extensions, pickle_file)
        with open('source_extensions.pkl', 'wb') as pickle_file:
            pickle.dump(source_extensions, pickle_file)

    print("TOTAL COUNT: " + str(total_count))

    extensions = list(total_extensions.keys())
    extensions.sort(key=lambda x: total_extensions[x], reverse=True)
    counts = [total_extensions[extension] for extension in extensions]

    # cut down extensions for space on graph
    extensions_reduced = extensions[:20]
    extensions_reduced.append("Remaining")
    counts_reduced = counts[:20]
    extensions_remainder = ', '.join(extensions[20:])
    counts_remainder = sum(counts[20:])
    counts_reduced.append(counts_remainder)

    # fig = plt.figure(figsize = (20, 10))

    # plt.bar(extensions_reduced, counts_reduced)
    # plt.xlabel("Extension")
    # plt.ylabel("Count of extension")
    # plt.title("Count of different extension types in PoC's")
    # plt.text(5, 3750, f"Remaining extensions: {extensions_remainder}", fontsize=10, wrap=True)
    # plt.show()
    # plt.savefig('result.png')

    df = pd.DataFrame()
    df['Extension'] = extensions_reduced
    df['Count'] = counts_reduced

    remainder_text = "\n".join(textwrap.wrap(f"Remaining extensions: {extensions_remainder}", 50))
    sns.set(rc={"figure.figsize":(20, 10)})
    plot = sns.barplot(data=df, x="Extension", y="Count")
    plot.text(14, 3000, remainder_text)
    fig = plot.get_figure()
    fig.savefig("extensions.pdf")
    fig.clf()

    source_names = {'exploitdb/': 'Exploit-DB', 'kernelhub/': 'Kernelhub', 'rhinoseclab/': 'Rhino Security Labs', 'poc-in-gh/': 'PoC-in-GitHub'}

    source_counts = {source_names[k]: sum(v.values()) for k, v in source_extensions.items()}
    print(source_counts)
    df2 = pd.DataFrame()
    df2['Source'] = source_counts.keys()
    df2['Count'] = source_counts.values()
    plot2 = sns.barplot(data=df2, x="Source", y="Count")
    fig2 = plot2.get_figure()
    fig2.savefig("figures/source-counts.pdf")
    fig2.clf()

    # Create a new DataFrame to store the tag counts
    tag_counts = pd.DataFrame(total_results['Tags'].explode().value_counts()).reset_index()

    # Rename the columns in the new DataFrame
    tag_counts.columns = ['Tag', 'Count']
    plot3 = sns.barplot(data=tag_counts, x="Tag", y="Count")
    plot3.set_xticklabels(plot3.get_xticklabels(), rotation=45, ha='right')  # Rotate x-axis labels
    plt.tight_layout()  # Adjust plot layout for better readability
    fig3 = plot3.get_figure()
    fig3.savefig('figures/tag-counts.pdf')

    print(total_extensions)
    log(total_extensions)
    # print(source_extensions)
    # log(source_extensions)
    log("##########################################")
    log("")
    log("")

    print("Finished computing stats!")

if __name__ == "__main__":
    compute_stats()
