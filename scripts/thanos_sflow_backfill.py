#!/usr/bin/env python3
"""Backfill the sflow-ixp-members recording rules into the Thanos bucket.

Usage: sflow_backfill.py <workdir> <start_epoch> <end_epoch> <step_s> <res> [--upload]

Writes one OpenMetrics file per UTC day (or per 14 days for coarse steps) from
thanos-query, turns it into TSDB blocks with promtool, and (with --upload)
uploads them with external labels prometheus=metrics.sfo02.sfmix.org,
backfill=sflow-members -- a separate compaction stream, so no block overlaps
the live Prometheus stream. end_epoch is exclusive.
"""
import json
import os
import shutil
import subprocess
import sys
import urllib.parse
import urllib.request

Q = "http://127.0.0.1:10904/api/v1/query_range"
RULES = {
    "sflow:ixp_peering_bps:sum_by_src": "sum by (src_asn, src_name) (sflow_ixp_peering_bps)",
    "sflow:ixp_peering_bps:sum_by_dst": "sum by (dst_asn, dst_name) (sflow_ixp_peering_bps)",
}
MAX_POINTS = 10000


def query(expr, start, end, step, res):
    body = urllib.parse.urlencode({
        "query": expr, "start": start, "end": end, "step": step,
        "max_source_resolution": res, "partial_response": "false", "dedup": "true",
    }).encode()
    for attempt in range(3):
        try:
            with urllib.request.urlopen(Q, body, timeout=60) as r:
                d = json.load(r)
            break
        except Exception as e:  # noqa: BLE001
            if attempt == 2:
                raise
            print(f"  retry {start}: {e}", flush=True)
    if d.get("status") != "success":
        raise RuntimeError(d)
    if d.get("warnings"):
        raise RuntimeError(f"warnings: {d['warnings']}")
    return d["data"]["result"]


def esc(v):
    return v.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def write_chunk(path, start, end, step, res):
    """Query [start, end) for every rule and write one OpenMetrics file."""
    win = step * MAX_POINTS
    n = 0
    with open(path, "w") as f:
        for name, expr in RULES.items():
            series = {}
            t = start
            while t < end:
                e = min(t + win, end) - step  # query_range end is inclusive
                for s in query(expr, t, e, step, res):
                    key = tuple(sorted(s["metric"].items()))
                    series.setdefault(key, []).extend(s["values"])
                t += win
            f.write(f"# TYPE {name} gauge\n")
            for key, vals in series.items():
                lbl = ",".join(f'{k}="{esc(v)}"' for k, v in key)
                for ts, v in vals:
                    f.write(f"{name}{{{lbl}}} {v} {ts}\n")
                    n += 1
        f.write("# EOF\n")
    return n


def run(cmd):
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"{cmd[:6]}...: {r.stdout[-2000:]}{r.stderr[-2000:]}")
    return r.stdout + r.stderr


def main():
    work, start, end, step, res = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4]), sys.argv[5]
    upload = "--upload" in sys.argv
    chunk = 86400 if step < 60 else 14 * 86400
    os.makedirs(work, exist_ok=True)
    t = start
    while t < end:
        # Align chunks to UTC day boundaries so each maps onto whole blocks.
        nxt = min((t // chunk + 1) * chunk, end)
        om = os.path.join(work, f"{t}.om")
        blocks = os.path.join(work, f"blocks-{t}")
        n = write_chunk(om, t, nxt, step, res)
        print(f"{t}-{nxt}: {n} samples", flush=True)
        if n:
            os.makedirs(blocks, exist_ok=True)
            run(["docker", "run", "--rm", "-u", "0", "-v", f"{work}:{work}",
                 "--entrypoint", "promtool", "prom/prometheus:v3.13.5",
                 "tsdb", "create-blocks-from", "openmetrics",
                 "--max-block-duration=24h", om, blocks])
            if upload:
                run(["docker", "run", "--rm", "-u", "0", "--network", "host",
                     "-v", "/opt/thanos/objstore.yml:/etc/thanos/objstore.yml:ro",
                     "-v", f"{blocks}:/blocks", "thanosio/thanos:v0.42.5",
                     "tools", "bucket", "upload-blocks",
                     "--objstore.config-file=/etc/thanos/objstore.yml", "--path=/blocks",
                     '--label=prometheus="metrics.sfo02.sfmix.org"',
                     '--label=backfill="sflow-members"'])
                shutil.rmtree(blocks)
        os.remove(om)
        t = nxt


if __name__ == "__main__":
    main()
