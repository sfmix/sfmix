#!/usr/bin/env python3
"""Show what a rendered VyOS config would change on a live box (doc 015).

  ssh mgmt-gw.sfo02.sfmix.org 'vbash -ic "show configuration commands"' > live.txt
  scripts/vyos_drift.py live.txt ansible/sfmix_network_devices.configs/mgmt-gw.sfo02/*.vyos_config.txt

Replays the rendered parts (`delete` / `set`, in order) on top of the live
config and prints the minimal change set: `delete` lines for live config the
templates own but no longer render, then `set` lines that are missing.
Empty output = the box matches the templates.
"""
import shlex
import sys

# Leaves that take a single value: a `set` replaces whatever is there.
SINGLE = {
    'description', 'cost', 'port', 'encrypted-password', 'key', 'type',
    'full-name', 'router-id', 'location', 'contact', 'cache-size',
    'metric-type', 'route-map', 'protocol', 'authorization', 'speed',
    'commit-revisions', 'host-name', 'domain-name', 'time-zone', 'level',
    'default-action', 'action', 'jump-target', 'translation', 'name',
}
NOISE = ("plaintext-password",)


def parse(lines):
    for line in lines:
        line = line.strip()
        if not line or line.startswith('#') or line.startswith('{'):
            continue
        try:
            toks = shlex.split(line)
        except ValueError:
            continue
        if toks and toks[0] in ('set', 'delete'):
            yield toks[0], tuple(toks[1:])


def single_valued(path):
    return len(path) >= 2 and (path[-2] in SINGLE or 'global-options' in path)


def main():
    live_file, *parts = sys.argv[1:]
    live = [p for op, p in parse(open(live_file)) if op == 'set'
            and not any(n in p for n in NOISE)]
    desired = list(live)
    for part in parts:
        for op, path in parse(open(part)):
            if op == 'delete':
                n = len(path)
                desired = [d for d in desired if d[:n] != path]
                continue
            if single_valued(path):
                desired = [d for d in desired if d[:-1] != path[:-1]]
            # A bare node (e.g. `set service ssh`) is implied by its children.
            if any(d[:len(path)] == path and len(d) > len(path) for d in desired):
                continue
            if path not in desired:
                desired.append(path)
    # Drop bare nodes that gained children.
    desired = [d for d in desired
               if not any(o[:len(d)] == d and len(o) > len(d) for o in desired)]
    live_set, want = set(live), set(desired)
    q = lambda p: ' '.join(shlex.quote(t) for t in p)
    for p in live:
        if p not in want:
            print('delete', q(p))
    for p in desired:
        if p not in live_set:
            print('set', q(p))


if __name__ == '__main__':
    main()
