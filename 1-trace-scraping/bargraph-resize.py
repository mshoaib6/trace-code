import os

import matplotlib.pyplot as plt
import pandas as pd

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FONT_SCALE = 2.88
FIGSIZE = (10, 6.5)
OUTPUT_PATH = os.path.join(BASE_DIR, "figures", "bargraph-resized.pdf")


def load_total_results():
    candidates = [
        os.path.join(BASE_DIR, "total_results.pkl"),
        os.path.join(BASE_DIR, "total_results_with_scores.pkl"),
        os.path.join(BASE_DIR, "total_results.csv"),
        os.path.join(BASE_DIR, "total_results_with_scores.csv"),
    ]
    last_error = None
    for path in candidates:
        if not os.path.isfile(path):
            continue
        if path.endswith(".pkl"):
            try:
                return pd.read_pickle(path)
            except Exception as exc:
                last_error = exc
                continue
        return pd.read_csv(path)
    if last_error:
        raise RuntimeError(f"Failed to read data file: {last_error}")
    raise FileNotFoundError("No total_results*.pkl or total_results*.csv found.")


def generate_bargraph():
    base_font_size = 10
    font_size = base_font_size * FONT_SCALE
    plt.rcParams.update(
        {
            "font.size": font_size,
            "axes.titlesize": font_size,
            "axes.labelsize": font_size,
            "xtick.labelsize": font_size,
            "ytick.labelsize": font_size,
        }
    )

    total_df = load_total_results()
    countdf = total_df.groupby(["CVE ID", "CVE-Year"]).size().reset_index(name="Count")
    countdf["CVE-Year"] = pd.to_numeric(countdf["CVE-Year"], errors="coerce")
    countdf = countdf.dropna(subset=["CVE-Year"])

    year_counts = countdf["CVE-Year"].value_counts().sort_index()

    fig, ax = plt.subplots(figsize=FIGSIZE)
    ax.bar(year_counts.index, year_counts.values)
    ax.set_xlabel("CVE Year")
    ax.set_ylabel("Count")
    ax.xaxis.label.set_size(font_size)
    ax.yaxis.label.set_size(font_size + 1)
    ax.tick_params(axis="x", labelsize=font_size, rotation=45)
    ax.tick_params(axis="y", labelsize=font_size)
    fig.tight_layout()

    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    fig.savefig(OUTPUT_PATH)
    plt.close(fig)


if __name__ == "__main__":
    generate_bargraph()
