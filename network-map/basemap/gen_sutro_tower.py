#!/usr/bin/env python3
"""Generate the (comically large) 3D Sutro Tower.

Writes website/static/map/sutro.json: a FeatureCollection of polygon pieces
with {base, height, color} properties that network-map.js draws as a
fill-extrusion layer. Procedurally modelled (openly-licensed mesh files would
need a whole glTF pipeline MapLibre doesn't have) to match the real
silhouette: three blade-legs that taper and LEAN INWARD from a wide base to
the waist, horizontal cross-braces, the double waist deck, three parallel
upper towers, and the iconic three-pronged crown of antenna spires at
different heights. Painted in night-muted international orange + white bands.
Scale is ~5x real (1.6 km to the tallest spire) per operator taste.

    python3 network-map/basemap/gen_sutro_tower.py
"""
import json
import math
import os

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.abspath(os.path.join(HERE, os.pardir, os.pardir,
                                   "website", "static", "map", "sutro.json"))

CENTER = (-122.45264, 37.75522)  # Sutro Tower, Mount Sutro
ORANGE = "#b85c38"  # international orange, night-muted
WHITE = "#cfd4d8"

M_LAT = 1.0 / 111320.0
M_LON = M_LAT / math.cos(math.radians(CENTER[1]))

LEGS = [90, 210, 330]   # bearings of the three legs (math convention, degrees)
R_BASE, R_WAIST = 340.0, 95.0   # leg-circle radius at ground / at the waist
H_WAIST = 950.0                  # waist height
H_TOWER = 1360.0                 # top of the parallel upper towers
SPIRES = [1600.0, 1500.0, 1460.0]  # antenna spire tips (tallest = the icon)


def lerp(a, b, t):
    return a + (b - a) * t


def rect(cx, cy, w, d, rot_deg):
    """Rectangle (w across, d radial) centred at metre-offset (cx, cy), rotated."""
    r = math.radians(rot_deg)
    cosr, sinr = math.cos(r), math.sin(r)
    pts = []
    for sx, sy in ((-1, -1), (1, -1), (1, 1), (-1, 1), (-1, -1)):
        x, y = sx * w / 2.0, sy * d / 2.0
        rx, ry = x * cosr - y * sinr, x * sinr + y * cosr
        pts.append([round(CENTER[0] + (cx + rx) * M_LON, 6),
                    round(CENTER[1] + (cy + ry) * M_LAT, 6)])
    return [pts]


def feat(ring, base, height, color):
    return {"type": "Feature",
            "properties": {"base": base, "height": height, "color": color},
            "geometry": {"type": "Polygon", "coordinates": ring}}


def leg_xy(bearing, radius):
    r = math.radians(bearing)
    return radius * math.cos(r), radius * math.sin(r)


def main():
    feats = []
    N = 16  # stacked segments per leg — the inward lean + taper (fine steps)
    # paint bands along the climb (roughly the real alternation: white every 3rd)
    bands = [WHITE if i % 3 == 2 else ORANGE for i in range(N)]

    for b in LEGS:
        rot = b + 90  # blade faces tangential, like the real legs
        for i in range(N):
            t0, t1 = i / float(N), (i + 1) / float(N)
            radius = lerp(R_BASE, R_WAIST, (t0 + t1) / 2.0)
            cx, cy = leg_xy(b, radius)
            w = lerp(200.0, 95.0, (t0 + t1) / 2.0)   # blade width across
            d = lerp(115.0, 60.0, (t0 + t1) / 2.0)   # blade depth radial
            feats.append(feat(rect(cx, cy, w, d, rot),
                              H_WAIST * t0, H_WAIST * t1, bands[i]))
        # upper tower: parallel (vertical) above the waist
        cx, cy = leg_xy(b, R_WAIST)
        feats.append(feat(rect(cx, cy, 78, 52, rot), H_WAIST, 1240, ORANGE))
        feats.append(feat(rect(cx, cy, 70, 46, rot), 1240, H_TOWER, WHITE))

    # horizontal cross-braces between adjacent legs (two levels)
    for frac in (0.32, 0.66):
        radius = lerp(R_BASE, R_WAIST, frac)
        z = H_WAIST * frac
        for i in range(3):
            x1, y1 = leg_xy(LEGS[i], radius)
            x2, y2 = leg_xy(LEGS[(i + 1) % 3], radius)
            mx, my = (x1 + x2) / 2.0, (y1 + y2) / 2.0
            length = math.hypot(x2 - x1, y2 - y1)
            rot = math.degrees(math.atan2(y2 - y1, x2 - x1))
            feats.append(feat(rect(mx, my, length, 26, rot), z - 14, z + 14, WHITE))

    # double waist deck (the two platform levels)
    for z0, z1, col, grow in ((920, 985, WHITE, 55), (1010, 1060, ORANGE, 30)):
        ring = []
        for b in LEGS:
            x, y = leg_xy(b, R_WAIST + grow)
            ring.append([round(CENTER[0] + x * M_LON, 6),
                         round(CENTER[1] + y * M_LAT, 6)])
        ring.append(ring[0])
        feats.append(feat([ring], z0, z1, col))

    # crown: crossarms linking the tower tops + the three antenna spires
    for i in range(3):
        x1, y1 = leg_xy(LEGS[i], R_WAIST)
        x2, y2 = leg_xy(LEGS[(i + 1) % 3], R_WAIST)
        mx, my = (x1 + x2) / 2.0, (y1 + y2) / 2.0
        length = math.hypot(x2 - x1, y2 - y1)
        rot = math.degrees(math.atan2(y2 - y1, x2 - x1))
        feats.append(feat(rect(mx, my, length, 26, rot), 1320, 1360, ORANGE))
    for b, tip in zip(LEGS, SPIRES):
        cx, cy = leg_xy(b, R_WAIST)
        # spire: a slim white mast with an even slimmer orange tip antenna
        feats.append(feat(rect(cx, cy, 34, 30, b + 90), H_TOWER, tip - 90, WHITE))
        feats.append(feat(rect(cx, cy, 18, 16, b + 90), tip - 90, tip, ORANGE))

    with open(OUT, "w") as fh:
        json.dump({"type": "FeatureCollection", "features": feats}, fh)
    print("wrote %s (%d pieces)" % (OUT, len(feats)))


if __name__ == "__main__":
    main()
