"""Build the public network-map (map.json) + private map-links.json from NetBox
+ committed geometry. Standalone entry point for local iteration and cron/manual
runs; the Django-Q2 task calls mapbuild.builder directly.

  manage.py build_map                     # write to settings.MAP_OUTPUT / MAP_LINKS_OUTPUT
  manage.py build_map --check             # report atlas<->topology drift, no writes
  manage.py build_map --dry-run           # print map.json to stdout, no writes
"""
import json

from django.conf import settings
from django.core.management.base import BaseCommand

from mapbuild import builder


class Command(BaseCommand):
    help = "Build the network-map map.json + map-links.json from NetBox + committed geometry."

    def add_arguments(self, parser):
        parser.add_argument("--out", default=getattr(settings, "MAP_OUTPUT",
                                                      "/var/lib/sfmix-map/map.json"))
        parser.add_argument("--links-out", default=getattr(settings, "MAP_LINKS_OUTPUT",
                                                           "/var/lib/sfmix-map/map-links.json"))
        parser.add_argument("--generation-seed",
                            help="stable seed for opaque ids (default: derived)")
        parser.add_argument("--now", help="override generated_at (reproducible builds)")
        parser.add_argument("--check", action="store_true",
                            help="report atlas<->topology drift; exit 1 on drift; no writes")
        parser.add_argument("--dry-run", action="store_true",
                            help="print map.json to stdout instead of writing")

    def handle(self, *args, **o):
        mapjson, links, drift = builder.build(generation_seed=o.get("generation_seed"),
                                               now=o.get("now"))
        if o["check"]:
            n = sum(len(v) for v in drift.values())
            self.stdout.write("cables: %d   sites: %d" % (len(mapjson["cables"]), len(mapjson["sites"])))
            self.stdout.write("MISSING atlas (auto-arc/routed): %s" % (drift["missing"] or "none"))
            self.stdout.write("STALE atlas (active, unseen):     %s" % (drift["stale"] or "none"))
            self.stdout.write("RETIRED-but-live:                 %s" % (drift["retired_live"] or "none"))
            self.stdout.write(self.style.WARNING("DRIFT DETECTED") if n
                              else self.style.SUCCESS("atlas in sync"))
            if n:
                raise SystemExit(1)
            return
        if o["dry_run"]:
            self.stdout.write(json.dumps(mapjson, indent=2))
            return
        builder.write_outputs(mapjson, links, o["out"], o["links_out"])
        self.stdout.write(self.style.SUCCESS(
            "wrote %s (%d cables) + %s" % (o["out"], len(mapjson["cables"]), o["links_out"])))
