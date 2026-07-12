from __future__ import annotations

import argparse

from tb_collector.config import load_config
from tb_collector.runner import run


def main() -> None:
    parser = argparse.ArgumentParser(prog="tb_collector")
    parser.add_argument("--config", required=True, help="Path to collector.yaml")
    args = parser.parse_args()
    run(load_config(args.config))


if __name__ == "__main__":
    main()
