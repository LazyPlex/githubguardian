"""Command-line interface for GitHub Guardian."""

import argparse


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="githubguardian",
        description="Scan authorized repository content for exposed secrets.",
    )
    parser.add_argument("repository", help="Repository in owner/name format.")
    args = parser.parse_args()

    print(f"GitHub Guardian: scanning {args.repository}")
    print("Repository fetching is the next implementation milestone.")


if __name__ == "__main__":
    main()
