"""Turn the fleet view model into what the pages show.

* slot states  -- ok / aging / worn / critical / empty / wished (+ donated flag)
* device facts -- age, memory filled vs. possible, slot fill strip
* needs        -- where a donation could go, with severity + suggested part
* spares       -- FRU part numbers in service vs. spares on hand
* flows        -- sankey layouts: needs -> devices, donors -> devices -> kinds
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import date
from typing import Any, Dict, Iterable, List, Optional, Tuple

from . import catalog
from .data import ROLE_LABELS, ROLE_ORDER

HOURS_PER_YEAR = 8766

KIND_LABELS = {
    "mainboard": "Mainboard",
    "cpu": "CPU",
    "memory": "Memory",
    "disk": "Drives",
    "psu": "Power",
    "fan": "Cooling",
    "linecard": "Line cards",
    "expansion": "Expansion",
    "transceiver": "Optics",
}
KIND_ORDER = list(KIND_LABELS)

CATEGORY_LABELS = {
    "wish": "Specific asks",
    "memory": "Memory",
    "disk": "Drives",
    "psu": "Power redundancy",
    "chassis": "Chassis refresh",
    "transceiver": "Optics",
}
SEVERITY_LABELS = {3: "Critical", 2: "High", 1: "Opportunity"}


def _d(s: Optional[str]) -> Optional[date]:
    if not s:
        return None
    try:
        return date.fromisoformat(str(s)[:10])
    except ValueError:
        return None


def years_between(a: Optional[date], b: date) -> Optional[float]:
    return None if a is None else round((b - a).days / 365.25, 1)


# ── slot state ─────────────────────────────────────────────────────────


def slot_state(slot: Dict[str, Any], today: date) -> str:
    m = slot.get("module")
    if not m:
        return "empty"
    if m.get("status") == "planned":
        return "wished"
    if m.get("status") == "failed":
        return "critical"
    endurance = m.get("endurance_used_pct")
    if endurance is not None and endurance >= 80:
        return "critical"
    age = years_between(_d(m.get("mfg_date")), today)
    poh = m.get("power_on_hours")
    if (endurance is not None and endurance >= 50) or (poh and poh >= 7 * HOURS_PER_YEAR):
        return "worn"
    if (age is not None and age >= 6) or (poh and poh >= 5 * HOURS_PER_YEAR):
        return "aging"
    return "ok"


# ── device enrichment ──────────────────────────────────────────────────


def enrich(fleet: List[Dict[str, Any]], today: Optional[date] = None) -> List[Dict[str, Any]]:
    """Annotate each device + slot in place with derived fields; returns fleet."""
    today = today or date.today()
    for dev in fleet:
        for s in dev["slots"]:
            s["state"] = slot_state(s, today)
            m = s.get("module") or {}
            s["donated"] = bool(m.get("donor"))
            s["age_years"] = years_between(_d(m.get("mfg_date")), today)
            poh = m.get("power_on_hours")
            s["power_on_years"] = round(poh / HOURS_PER_YEAR, 1) if poh else None
        dev["slots"].sort(key=lambda s: (KIND_ORDER.index(s["kind"]) if s["kind"] in KIND_ORDER else 99, _natural(s["bay"])))

        # Age: chassis build date, else the CPU generation's launch year.
        built = _d(dev.get("mfg_date"))
        dev["age_basis"] = "built"
        if built is None:
            years = [catalog.cpu_year((s.get("module") or {}).get("model", "")) for s in dev["slots"] if s["kind"] == "cpu"]
            years = [y for y in years if y]
            if years:
                built = date(min(years), 7, 1)
                dev["age_basis"] = "cpu generation"
        dev["built"] = built
        dev["built_year"] = built.year if built else None
        dev["age_years"] = years_between(built, today)

        # Memory filled vs. possible.
        mb = next((s.get("module") for s in dev["slots"] if s["kind"] == "mainboard" and s.get("module")), None)
        dimms = [s for s in dev["slots"] if s["kind"] == "memory"]
        installed_gb = sum(int((s.get("module") or {}).get("attributes", {}).get("size") or 0) for s in dimms if s["state"] not in ("empty", "wished"))
        max_gb = (mb or {}).get("attributes", {}).get("max_memory_gb")
        dev["memory"] = (
            {
                "installed_gb": installed_gb,
                "max_gb": max_gb,
                "slots": len(dimms),
                "filled": sum(1 for s in dimms if s["state"] not in ("empty", "wished")),
                "pct": round(100 * installed_gb / max_gb) if max_gb else None,
            }
            if dimms
            else None
        )

        # Slot fill summary per kind (drives the strip on fleet cards).
        groups = []
        for kind in KIND_ORDER:
            ss = [s for s in dev["slots"] if s["kind"] == kind]
            if ss:
                groups.append({"kind": kind, "label": KIND_LABELS[kind], "slots": ss,
                               "filled": sum(1 for s in ss if s["state"] not in ("empty", "wished")),
                               "total": len(ss)})
        dev["groups"] = groups
        dev["worst"] = _worst([s["state"] for s in dev["slots"]])
        dev["role_label"] = ROLE_LABELS.get(dev["role"], dev["role"])
        dev["successor"] = catalog.chassis_successor(dev["model"]) or catalog.chassis_successor(
            next((s["module"]["model"] for s in dev["slots"] if s["kind"] == "mainboard" and s.get("module")), "")
        )
    return fleet


def _natural(s: str) -> Tuple:
    import re

    return tuple(int(t) if t.isdigit() else t for t in re.split(r"(\d+)", s))


def _worst(states: Iterable[str]) -> str:
    order = ["critical", "worn", "aging", "ok"]
    present = set(states)
    for s in order:
        if s in present:
            return s
    return "ok"


def by_role(fleet: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out = []
    for role in ROLE_ORDER + sorted({d["role"] for d in fleet} - set(ROLE_ORDER)):
        devs = sorted((d for d in fleet if d["role"] == role), key=lambda d: (-(d["age_years"] or 0), d["name"]))
        if devs:
            out.append({"role": role, "label": ROLE_LABELS.get(role, role), "devices": devs})
    return out


# ── needs: where a donation could go ───────────────────────────────────


@dataclass
class Need:
    category: str
    severity: int
    device: str
    title: str
    detail: str
    suggestion: str
    bays: List[str] = field(default_factory=list)
    units: int = 1  # how many parts this need could absorb

    @property
    def category_label(self) -> str:
        return CATEGORY_LABELS.get(self.category, self.category)

    @property
    def severity_label(self) -> str:
        return SEVERITY_LABELS[self.severity]


def needs(fleet: List[Dict[str, Any]], today: Optional[date] = None) -> List[Need]:
    today = today or date.today()
    out: List[Need] = []
    for dev in fleet:
        name = dev["name"]
        slots = dev["slots"]

        for s in slots:
            if s["state"] == "wished":
                m = s["module"]
                out.append(Need("wish", 3, name, f"{m['manufacturer']} {m['model']}",
                                f"Planned for {s['bay']}" + (f" — pledged by {m['donor']}" if m.get("donor") else ""),
                                m.get("description") or m["model"], [s["bay"]]))

        # Memory
        mem = dev.get("memory")
        empty_dimms = [s for s in slots if s["kind"] == "memory" and s["state"] == "empty"]
        if mem and empty_dimms:
            per = (mem["max_gb"] // mem["slots"]) if mem.get("max_gb") and mem.get("slots") else None
            room = (per * len(empty_dimms)) if per else None
            sev = 2 if mem["installed_gb"] < 128 else 1
            out.append(Need(
                "memory", sev, name,
                f"{len(empty_dimms)} empty DIMM slot{'s' if len(empty_dimms) != 1 else ''}",
                f"{mem['installed_gb']} GB installed" + (f" of {mem['max_gb']:,} GB possible" if mem.get("max_gb") else "")
                + (f"; room for +{room:,} GB" if room else ""),
                catalog.memory_suggestion(empty_dimms[0].get("accepts") or {}, per),
                [s["bay"] for s in empty_dimms], len(empty_dimms)))

        # Drives
        disks = [s for s in slots if s["kind"] == "disk" and s.get("module") and s["state"] != "wished"]
        crit = [s for s in disks if s["state"] == "critical"]
        worn = [s for s in disks if s["state"] in ("worn", "aging") and s not in crit]
        for group, sev, verb in ((crit, 3, "near end of life"), (worn, 2, "worn / aging")):
            if not group:
                continue
            m0 = group[0]["module"]
            ssd = (m0.get("attributes") or {}).get("type") in ("SSD", "NVME")
            endurance = [s["module"].get("endurance_used_pct") for s in group if s["module"].get("endurance_used_pct") is not None]
            poh = [s["power_on_years"] for s in group if s.get("power_on_years")]
            facts = []
            if endurance:
                facts.append(f"{max(endurance)}% of rated write endurance used")
            if poh:
                facts.append(f"up to {max(poh)} years powered on")
            if any(catalog.is_consumer_drive(s["module"]["model"]) for s in group):
                facts.append("consumer-class drives")
            out.append(Need("disk", sev, name, f"{len(group)} drive{'s' if len(group) != 1 else ''} {verb}",
                            f"{m0['manufacturer']} {m0['model']}: " + ", ".join(facts),
                            catalog.SSD_SUGGESTION if ssd else catalog.HDD_SUGGESTION,
                            [s["bay"] for s in group], len(group)))
        empty_bays = [s for s in slots if s["kind"] == "disk" and s["state"] == "empty" and (s.get("accepts") or {}).get("bus") in ("SES", "NVMe")]
        if empty_bays:
            out.append(Need("disk", 1, name, f"{len(empty_bays)} empty drive bay{'s' if len(empty_bays) != 1 else ''}",
                            "Hot-swap bays with nothing in them", catalog.SSD_SUGGESTION,
                            [s["bay"] for s in empty_bays], len(empty_bays)))

        # Power
        psus = [s for s in slots if s["kind"] == "psu"]
        empty_psu = [s for s in psus if s["state"] == "empty"]
        live_psu = [s for s in psus if s.get("module") and s["state"] not in ("wished",)]
        if empty_psu:
            model = live_psu[0]["module"]["model"] if live_psu else (empty_psu[0].get("accepts") or {}).get("part_number", "matching PSU")
            sev = 3 if len(live_psu) <= 1 else 1
            out.append(Need("psu", sev, name,
                            "No redundant power supply" if len(live_psu) <= 1 else f"{len(empty_psu)} empty PSU slot{'s' if len(empty_psu) != 1 else ''}",
                            f"{len(live_psu)} of {len(psus)} PSU slots populated", f"{live_psu[0]['module']['manufacturer'] + ' ' if live_psu else ''}{model}",
                            [s["bay"] for s in empty_psu], len(empty_psu)))
        failed_psu = [s for s in live_psu if s["state"] == "critical"]
        if failed_psu:
            out.append(Need("psu", 3, name, "Failed power supply", ", ".join(s["bay"] for s in failed_psu),
                            failed_psu[0]["module"]["model"], [s["bay"] for s in failed_psu], len(failed_psu)))

        # Chassis
        if dev.get("age_years") and dev["age_years"] >= 6:
            succ = dev.get("successor") or {}
            out.append(Need("chassis", 2 if dev["age_years"] >= 7 else 1, name,
                            f"{dev['model']} from {dev['built_year']} ({dev['age_years']:.0f} years)",
                            succ.get("why", "Past a typical 5–7 year service life."),
                            succ.get("suggest", "A current-generation replacement"), [], 1))

        # Optics: empty cages = room to connect new participants.
        by_ff: Dict[str, List[str]] = defaultdict(list)
        for s in slots:
            if s["kind"] == "transceiver" and s["state"] == "empty":
                by_ff[(s.get("accepts") or {}).get("form_factor") or "?"].append(s["bay"])
        for ff, bays in sorted(by_ff.items()):
            out.append(Need("transceiver", 1, name, f"{len(bays)} empty {ff} cage{'s' if len(bays) != 1 else ''}",
                            "Ready for new participant ports once optics are in hand",
                            catalog.OPTIC_SUGGESTIONS.get(ff, f"{ff} optic"), bays, len(bays)))

    out.sort(key=lambda n: (-n.severity, list(CATEGORY_LABELS).index(n.category), n.device))
    return out


def need_summary(ns: List[Need]) -> List[Dict[str, Any]]:
    cats: Dict[str, Dict[str, Any]] = {}
    for n in ns:
        c = cats.setdefault(n.category, {"category": n.category, "label": n.category_label, "units": 0,
                                         "items": 0, "devices": set(), "severity": 0})
        c["units"] += n.units
        c["items"] += 1
        c["devices"].add(n.device)
        c["severity"] = max(c["severity"], n.severity)
    out = []
    for key in CATEGORY_LABELS:
        if key in cats:
            c = cats[key]
            c["devices"] = len(c["devices"])
            c["severity_label"] = SEVERITY_LABELS[c["severity"]]
            out.append(c)
    return out


# ── spares ─────────────────────────────────────────────────────────────

SPARE_KINDS = ("psu", "fan", "transceiver", "disk", "memory")


def spares(fleet: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """FRU part numbers in service. Spares on hand are not tracked yet -> 0."""
    counts: Counter = Counter()
    devices: Dict[Tuple[str, str, str], set] = defaultdict(set)
    for dev in fleet:
        for s in dev["slots"]:
            m = s.get("module")
            if s["kind"] in SPARE_KINDS and m and s["state"] != "wished":
                key = (s["kind"], m["manufacturer"], m["model"])
                counts[key] += 1
                devices[key].add(dev["name"])
    rows = [
        {"kind": KIND_LABELS[k[0]], "manufacturer": k[1], "model": k[2], "in_service": n,
         "devices": len(devices[k]), "spares": 0}
        for k, n in counts.items()
    ]
    rows.sort(key=lambda r: (-r["devices"], -r["in_service"], r["model"]))
    return rows


# ── headline stats ─────────────────────────────────────────────────────


def stats(fleet: List[Dict[str, Any]], ns: List[Need]) -> Dict[str, Any]:
    ages = [d["age_years"] for d in fleet if d.get("age_years") is not None]
    oldest = min((d for d in fleet if d.get("built")), key=lambda d: d["built"], default=None)
    slots = [s for d in fleet for s in d["slots"]]
    mem = [d["memory"] for d in fleet if d.get("memory")]
    return {
        "devices": len(fleet),
        "median_age": sorted(ages)[len(ages) // 2] if ages else None,
        "oldest": oldest,
        "slots": len(slots),
        "parts": sum(1 for s in slots if s.get("module") and s["state"] != "wished"),
        "empty": sum(1 for s in slots if s["state"] == "empty"),
        "critical": sum(1 for s in slots if s["state"] == "critical"),
        "worn": sum(1 for s in slots if s["state"] in ("worn", "aging")),
        "donated": sum(1 for s in slots if s.get("donated")) + sum(1 for d in fleet if d.get("donor")),
        "mem_installed_gb": sum(m["installed_gb"] for m in mem),
        "mem_max_gb": sum(m["max_gb"] or 0 for m in mem),
        "urgent_needs": sum(1 for n in ns if n.severity >= 3),
        "spares": 0,
    }


# ── donations ledger ───────────────────────────────────────────────────


def donations(fleet: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    rows = []
    for dev in fleet:
        if dev.get("donor"):
            rows.append({"donor": dev["donor"], "donated_on": dev.get("donated_on"), "device": dev["name"],
                         "bay": "", "kind": "chassis", "kind_label": "Chassis",
                         "part": f"{dev['manufacturer']} {dev['model']}", "status": "active"})
        for s in dev["slots"]:
            m = s.get("module") or {}
            if m.get("donor"):
                rows.append({"donor": m["donor"], "donated_on": m.get("donated_on"), "device": dev["name"],
                             "bay": s["bay"], "kind": s["kind"], "kind_label": KIND_LABELS.get(s["kind"], s["kind"]),
                             "part": f"{m['manufacturer']} {m['model']}",
                             "status": "pledged" if m.get("status") == "planned" else "installed"})
    rows.sort(key=lambda r: (str(r["donated_on"] or ""), r["donor"]), reverse=True)
    return rows


# ── sankey layout ──────────────────────────────────────────────────────


def sankey(links: List[Tuple[str, str, float]], columns: List[List[str]], *, width: int = 900,
           node_w: int = 14, gap: int = 10, height: Optional[int] = None,
           colors: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """Minimal left-to-right sankey: returns node rects + link paths for an SVG.

    ``columns`` fixes node order per column; node size = max(in, out) value.
    """
    colors = colors or {}
    val_in: Counter = Counter()
    val_out: Counter = Counter()
    for a, b, v in links:
        val_out[a] += v
        val_in[b] += v
    size = {n: max(val_in[n], val_out[n]) for col in columns for n in col}
    tallest = max((sum(size[n] for n in col) for col in columns), default=1) or 1
    max_nodes = max((len(c) for c in columns), default=1)
    height = height or max(220, 22 * max_nodes + 60)
    scale = (height - gap * (max_nodes - 1)) / tallest
    xstep = (width - node_w) / max(1, len(columns) - 1)
    nodes: Dict[str, Dict[str, Any]] = {}
    for ci, col in enumerate(columns):
        total = sum(size[n] for n in col) * scale + gap * (len(col) - 1)
        y = (height - total) / 2
        for n in col:
            h = max(2.0, size[n] * scale)
            nodes[n] = {"id": n, "label": n.split("::")[-1], "x": ci * xstep, "y": y, "h": h,
                        "value": size[n], "col": ci, "anchor": "start" if ci < len(columns) - 1 else "end",
                        "color": colors.get(n, ""), "_out": y, "_in": y}
            y += h + gap
    paths = []
    for a, b, v in sorted(links, key=lambda l: (nodes[l[0]]["y"], nodes[l[1]]["y"])):
        na, nb = nodes[a], nodes[b]
        t = v * scale
        x0, x1 = na["x"] + node_w, nb["x"]
        y0, y1 = na["_out"] + t / 2, nb["_in"] + t / 2
        na["_out"] += t
        nb["_in"] += t
        xm = (x0 + x1) / 2
        paths.append({"d": f"M{x0:.1f},{y0:.1f} C{xm:.1f},{y0:.1f} {xm:.1f},{y1:.1f} {x1:.1f},{y1:.1f}",
                      "w": max(1.0, t), "src": a, "dst": b, "value": v,
                      "color": na["color"] or nb["color"]})
    last = len(columns) - 1
    for n in nodes.values():
        # First column labels sit left of the nodes, the rest to the right, so
        # no label is drawn over the bands.
        n["anchor"] = "end" if n["col"] == 0 and last > 0 else "start"
        n["lx"] = n["x"] - 6 if n["anchor"] == "end" else n["x"] + node_w + 6
        n["ly"] = n["y"] + n["h"] / 2
    return {"width": width, "height": height, "node_w": node_w, "nodes": list(nodes.values()), "links": paths}


CATEGORY_COLORS = {
    "wish": "var(--c-wish)",
    "memory": "var(--c-memory)",
    "disk": "var(--c-disk)",
    "psu": "var(--c-psu)",
    "chassis": "var(--c-chassis)",
    "transceiver": "var(--c-optic)",
}


def needs_flow(ns: List[Need], include_optics: bool = False) -> Optional[Dict[str, Any]]:
    """Category -> device, weighted by severity × units (log-damped)."""
    import math

    agg: Counter = Counter()
    for n in ns:
        if n.category == "transceiver" and not include_optics:
            continue
        agg[(n.category, n.device)] += n.severity * (1 + math.log2(n.units))
    if not agg:
        return None
    cats = [c for c in CATEGORY_LABELS if any(k[0] == c for k in agg)]
    dev_weight: Counter = Counter()
    for (c, d), v in agg.items():
        dev_weight[d] += v
    devs = [d for d, _ in dev_weight.most_common()]
    links = [(f"c::{CATEGORY_LABELS[c]}", f"d::{d}", v) for (c, d), v in agg.items()]
    colors = {f"c::{CATEGORY_LABELS[c]}": CATEGORY_COLORS[c] for c in cats}
    return sankey(links, [[f"c::{CATEGORY_LABELS[c]}" for c in cats], [f"d::{d}" for d in devs]], colors=colors)


def donations_flow(rows: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not rows:
        return None
    a: Counter = Counter()
    b: Counter = Counter()
    for r in rows:
        a[(f"o::{r['donor']}", f"d::{r['device']}")] += 1
        b[(f"d::{r['device']}", f"k::{r['kind_label']}")] += 1
    donors = sorted({k[0] for k in a}, key=lambda n: -sum(v for k, v in a.items() if k[0] == n))
    devs = sorted({k[1] for k in a}, key=lambda n: -sum(v for k, v in a.items() if k[1] == n))
    kinds = sorted({k[1] for k in b}, key=lambda n: -sum(v for k, v in b.items() if k[1] == n))
    kind_color = {f"k::{KIND_LABELS.get(k, k)}": CATEGORY_COLORS.get(k, "") for k in KIND_LABELS}
    kind_color["k::Chassis"] = CATEGORY_COLORS["chassis"]
    return sankey([(x, y, v) for (x, y), v in (a + b).items()], [donors, devs, kinds], colors=kind_color)
