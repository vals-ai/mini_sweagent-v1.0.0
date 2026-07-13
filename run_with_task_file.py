#!/usr/bin/env python3

import os
import sys


def main() -> None:
    if len(sys.argv) < 2:
        raise SystemExit("Usage: run_with_task_file.py <task-file> [mini args...]")

    task_file = sys.argv[1]
    mini_args = sys.argv[2:]

    with open(task_file, "r", encoding="utf-8") as file:
        task = file.read()

    os.execvp("mini", ["mini", *mini_args, "--task", task])


if __name__ == "__main__":
    main()
