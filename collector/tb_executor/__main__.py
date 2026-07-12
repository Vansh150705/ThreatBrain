from __future__ import annotations

import argparse

from tb_executor.config import load_executor_config
from tb_executor.runner import run


def main() -> None:
    parser = argparse.ArgumentParser(prog="tb_executor")
    parser.add_argument("--config", required=True, help="Path to executor.yaml")
    args = parser.parse_args()
    run(load_executor_config(args.config))


if __name__ == "__main__":
    main()
