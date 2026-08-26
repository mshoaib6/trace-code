import os

import matplotlib.pyplot as plt
import pandas as pd

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FONT_SCALE = 2.0
FIGSIZE = (10, 3.6)
OUTPUT_PATH = os.path.join(BASE_DIR, "figures", "boxplot-resized.pdf")


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


def generate_boxplot():
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

    fig, ax = plt.subplots(figsize=FIGSIZE)
    countdf.boxplot(column="Count", by="CVE-Year", ax=ax)
    ax.set_xlabel("CVE Year")
    ax.set_ylabel("Count")
    ax.set_title("POCs per CVE grouped by Year")
    ax.set_yscale("log")
    ax.set_xticklabels(ax.get_xticklabels(), rotation=45, ha="right")
    fig.suptitle("")
    fig.tight_layout()

    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    fig.savefig(OUTPUT_PATH)
    plt.close(fig)


if __name__ == "__main__":
    generate_boxplot()
