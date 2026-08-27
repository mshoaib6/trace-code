from convert_graph import convert_graph
import argparse
import os


def parse_args():
    parser = argparse.ArgumentParser(description="Generate a template graph from a Python PoC file.")
    parser.add_argument("filename", help="Path to the Python PoC file.")
    parser.add_argument("--format", choices=["txt", "dot"], default="txt",
                        help="Output format: 'txt' (stage-3-ready NODE/EDGE) or 'dot' (legacy pydot).")
    parser.add_argument("--locus", choices=["auto", "local", "remote"], default="auto",
                        help="Invocation locus: whether the PoC runs on ('local') or "
                             "against ('remote') the monitored target. 'auto' infers it.")
    return parser.parse_args()


def main():
    args = parse_args()
    foldername = os.path.dirname(args.filename)
    print(foldername)
    convert_graph(args.filename, foldername, out_format=args.format,
                  locus_mode=args.locus)

if __name__ == "__main__":
    main()
