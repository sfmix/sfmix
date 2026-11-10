#!/usr/bin/env python3
"""Publish what time ranges the Thanos bucket holds, per resolution, as
node_exporter textfile metrics (design doc 012).

Thanos exposes block counts but not coverage, so this lists the bucket with
`thanos tools bucket ls -o json` and writes, per resolution (raw/5m/1h):

  thanos_bucket_blocks              blocks
  thanos_bucket_min_time_seconds    oldest sample
  thanos_bucket_max_time_seconds    newest sample
  thanos_bucket_samples             samples
  thanos_bucket_size_bytes          block files (index + chunks + meta)

plus thanos_bucket_coverage_success / _last_run_timestamp_seconds.
Usage: thanos_bucket_coverage.py <thanos-image> <objstore.yml> <out.prom>
"""
import json
import os
import subprocess
import sys
import time

RES = {0: "raw", 300000: "5m", 3600000: "1h"}


def blocks(image, objstore):
    out = subprocess.run(
        ["docker", "run", "--rm", "--network", "host", "--user", "65534:65534",
         "-v", f"{objstore}:/objstore.yml:ro", image,
         "tools", "bucket", "ls", "--objstore.config-file=/objstore.yml", "-o", "json"],
        capture_output=True, text=True, timeout=600, check=True).stdout
    dec, i = json.JSONDecoder(), 0
    while True:
        j = out.find("{", i)
        if j < 0:
            return
        try:
            obj, i = dec.raw_decode(out, j)
        except json.JSONDecodeError:
            i = j + 1
            continue
        if isinstance(obj, dict) and "ulid" in obj:
            yield obj


def main(image, objstore, dest):
    agg = {name: {"blocks": 0, "min": None, "max": None, "samples": 0, "bytes": 0}
           for name in RES.values()}
    ok = 1
    try:
        for b in blocks(image, objstore):
            a = agg[RES.get(b["thanos"]["downsample"]["resolution"], "raw")]
            a["blocks"] += 1
            a["min"] = b["minTime"] if a["min"] is None else min(a["min"], b["minTime"])
            a["max"] = b["maxTime"] if a["max"] is None else max(a["max"], b["maxTime"])
            a["samples"] += b["stats"].get("numSamples", 0)
            a["bytes"] += sum(f.get("size_bytes", 0) for f in b["thanos"].get("files") or [])
    except Exception as e:  # keep last good values out; report failure
        print(f"bucket ls failed: {e}", file=sys.stderr)
        ok = 0

    lines = []

    def metric(name, help_, rows):
        lines.append(f"# HELP {name} {help_}")
        lines.append(f"# TYPE {name} gauge")
        lines.extend(rows)

    if ok:
        for key, name, help_, scale in [
            ("blocks", "thanos_bucket_blocks", "Blocks in the Thanos bucket.", 1),
            ("min", "thanos_bucket_min_time_seconds", "Oldest sample in the bucket.", 1000),
            ("max", "thanos_bucket_max_time_seconds", "Newest sample in the bucket.", 1000),
            ("samples", "thanos_bucket_samples", "Samples in the bucket.", 1),
            ("bytes", "thanos_bucket_size_bytes", "Size of block files in the bucket.", 1),
        ]:
            rows = [f'{name}{{resolution="{r}"}} {a[key] / scale:.3f}'
                    for r, a in agg.items() if a[key] is not None and a["blocks"]]
            metric(name, help_, rows)
    metric("thanos_bucket_coverage_success", "1 if the last bucket listing worked.",
           [f"thanos_bucket_coverage_success {ok}"])
    metric("thanos_bucket_coverage_last_run_timestamp_seconds", "Last coverage run.",
           [f"thanos_bucket_coverage_last_run_timestamp_seconds {time.time():.0f}"])

    tmp = dest + ".tmp"
    with open(tmp, "w") as f:
        f.write("\n".join(lines) + "\n")
    os.chmod(tmp, 0o644)
    os.replace(tmp, dest)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:4]))
