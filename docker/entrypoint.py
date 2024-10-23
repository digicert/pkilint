#!/usr/bin/env python3

import sys
import os
import importlib


def main():
    if len(sys.argv) < 2:
        print("Executable not specified", file=sys.stderr)

        return 1

    cmd = sys.argv[1]
    args = sys.argv[2:]

    try:
        module = importlib.import_module(f"pkilint.bin.{cmd}")

        main_func = getattr(module, "main")
    except (ImportError, AttributeError):
        os.execvp(cmd, [cmd] + args)

    return main_func(args)


if __name__ == "__main__":
    sys.exit(main())
