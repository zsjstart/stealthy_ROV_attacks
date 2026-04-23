import argparse
from run import compute_impact


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run compute_impact with configurable arguments."
    )

    parser.add_argument(
        "strategies",
        nargs="+",
        help="One or more strategies to pass to compute_impact, e.g. random_choice",
    )
    parser.add_argument(
        "--rel-file",
        default="caida.txt",
        help="Path to the relationship file (default: caida.txt)",
    )
    parser.add_argument(
        "--device",
        default="cuda:0",
        help="Device to use, e.g. cuda:0 or cpu (default: cuda:0)",
    )

    args = parser.parse_args()

    compute_impact(
        args.strategies,
        rel_file=args.rel_file,
        device=args.device,
    )


if __name__ == "__main__":
    main()
