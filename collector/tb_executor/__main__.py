from __future__ import annotations

import argparse
import logging

from tb_executor.config import load_executor_config
from tb_executor.runner import run


def main() -> None:
    parser = argparse.ArgumentParser(prog="tb_executor")
    parser.add_argument("--config", required=True, help="Path to executor.yaml")
    parser.add_argument("-v", "--verbose", action="store_true", help="Debug logging")
    args = parser.parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    run(load_executor_config(args.config))


if __name__ == "__main__":
    main()
