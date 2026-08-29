import pandas as pd
import numpy as np

def copy_tags():
    print("Copying tags...")
    df = pd.read_pickle('total_results.pkl')

    tags = df['Tags'].apply(lambda x: [] if type(x) is not list else list(x))
    df['Tags'] = tags
    original = df.copy()

    tags = tags.apply(lambda x: len(x) == 0)

    df.loc[tags, 'Tags'] = np.nan

    df['Tags'] = df.groupby('CVE ID')['Tags'].transform(lambda x: x.ffill().bfill())

    df['Tags'] = df['Tags'].apply(lambda x: [] if type(x) is not list else x)

    num_modified_rows = (df['Tags'] != original['Tags']).sum()

    print(str(num_modified_rows) + "rows modified")

    df.to_csv('total_results.csv')
    df.to_pickle('total_results.pkl')
    print("Finished copying tags!")