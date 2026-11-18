from __future__ import annotations

import argparse
import logging

from tb_collector.config import load_config
from tb_collector.runner import run


def main() -> None:
    parser = argparse.ArgumentParser(prog="tb_collector")
    parser.add_argument("--config", required=True, help="Path to collector.yaml")
    parser.add_argument("-v", "--verbose", action="store_true", help="Debug logging")
    args = parser.parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    run(load_config(args.config))


if __name__ == "__main__":
    main()
