#!/usr/bin/env python
import json
import sys
import argparse


def get_inventory():
    inventory = {
        "_meta": {
            "hostvars": {
                "all": {
                    "participants": ["participant1", "participant2", "participant3"]
                }
            }
        },
    }
    return inventory


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--list", action="store_true")
    args = parser.parse_args()

    if args.list:
        inventory = get_inventory()
        print(json.dumps(inventory))
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
