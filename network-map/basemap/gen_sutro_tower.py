#!/usr/bin/env python3
"""Generate the (comically large) 3D Sutro Tower.

Writes website/static/map/sutro.json: a FeatureCollection of polygon pieces
with {base, height, color} properties that network-map.js draws as a
fill-extrusion layer. Procedurally modelled (openly-licensed mesh files would
need a whole glTF pipeline MapLibre doesn't have) to match the real silhouette.

Real proportions we lean on (Wikipedia): three blade-legs on a 150 ft base
triangle that taper and LEAN INWARD to a narrow 60 ft "waist" high up the
tower, then the antenna section SPLAYS BACK OUT to a 100 ft triangle carrying
three candelabra towers bristling with stacked horizontal crossarms, each
topped by a tall slender antenna mast (the tallest tip = the icon).

Smoothing notes: fill-extrusion can only draw vertical prisms with a flat top
and bottom, so a leaning/tapering member has to be approximated by a stack of
segments. The trick to killing the "staircase" look is small steps — we use
many fine segments so the inward lean and the taper read as smooth. The
antenna masts likewise taper through several segments down to a thin needle so
they read as tall spires rather than stubby blocks.

Painted in night-muted international orange + white bands. Scale is ~5x real
(1.6 km to the tallest spire) per operator taste.

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
R_BASE = 340.0          # leg-circle radius at the ground (150 ft triangle)
R_WAIST = 95.0          # leg-circle radius at the narrow waist (60 ft triangle)
R_ANT = 158.0           # antenna-section radius — splays back out (100 ft tri.)
H_WAIST = 1020.0        # waist height (real waist sits high up the tower)
H_SPLAY = 1160.0        # height where the antenna towers finish splaying out
H_TOWER = 1420.0        # top of the candelabra body (crossarm stack)
SPIRES = [1660.0, 1540.0, 1490.0]  # antenna mast tips (tallest = the icon)


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


def band(i, offset=0):
    """Paint band along the climb — roughly white every 3rd, like the real tower."""
    return WHITE if (i + offset) % 3 == 2 else ORANGE


def leg_stack(feats, b, r0, r1, z0, z1, w0, w1, d0, d1, n, band0=0):
    """Stack of fine tapered segments along one leg/mast — moves radially from r0
    to r1 while climbing z0..z1 and tapering (w,d). Many small steps => smooth."""
    rot = b + 90  # blade faces tangential, like the real legs
    for i in range(n):
        t0, t1 = i / float(n), (i + 1) / float(n)
        tm = (t0 + t1) / 2.0
        cx, cy = leg_xy(b, lerp(r0, r1, tm))
        feats.append(feat(rect(cx, cy, lerp(w0, w1, tm), lerp(d0, d1, tm), rot),
                          lerp(z0, z1, t0), lerp(z0, z1, t1), band(i, band0)))


def crossarm(feats, b, radius, z, length, thick, color):
    """A candelabra crossarm: a broad horizontal antenna bar (tangential) plus a
    shorter radial bar, so it reads as a cross from every viewing angle."""
    cx, cy = leg_xy(b, radius)
    feats.append(feat(rect(cx, cy, length, thick, b + 90), z - thick, z + thick, color))
    feats.append(feat(rect(cx, cy, length * 0.55, thick, b), z - thick, z + thick, color))


def main():
    feats = []

    # --- three blade-legs: taper + lean inward from wide base to narrow waist ---
    N = 46  # fine steps => the inward lean and width taper read as smooth
    for b in LEGS:
        leg_stack(feats, b, R_BASE, R_WAIST, 0.0, H_WAIST,
                  200.0, 95.0, 115.0, 60.0, N)

    # --- horizontal cross-braces knitting adjacent legs (three levels) ---
    for frac in (0.28, 0.55, 0.82):
        radius = lerp(R_BASE, R_WAIST, frac)
        z = H_WAIST * frac
        for i in range(3):
            x1, y1 = leg_xy(LEGS[i], radius)
            x2, y2 = leg_xy(LEGS[(i + 1) % 3], radius)
            mx, my = (x1 + x2) / 2.0, (y1 + y2) / 2.0
            length = math.hypot(x2 - x1, y2 - y1)
            rot = math.degrees(math.atan2(y2 - y1, x2 - x1))
            feats.append(feat(rect(mx, my, length, 24, rot), z - 12, z + 12, WHITE))

    # --- double waist deck (the two maintenance-platform levels) ---
    for z0, z1, col, grow in ((H_WAIST - 90, H_WAIST - 25, WHITE, 55),
                              (H_WAIST + 5, H_WAIST + 55, ORANGE, 30)):
        ring = []
        for b in LEGS:
            x, y = leg_xy(b, R_WAIST + grow)
            ring.append([round(CENTER[0] + x * M_LON, 6),
                         round(CENTER[1] + y * M_LAT, 6)])
        ring.append(ring[0])
        feats.append(feat([ring], z0, z1, col))

    # --- antenna section: splay back OUT, candelabra crossarms, slender masts ---
    for b, tip in zip(LEGS, SPIRES):
        # splay: the tower widens outward from the waist to the antenna triangle
        leg_stack(feats, b, R_WAIST, R_ANT, H_WAIST, H_SPLAY,
                  86.0, 74.0, 58.0, 50.0, 8)
        # candelabra body: vertical tower carrying the crossarm stack
        leg_stack(feats, b, R_ANT, R_ANT, H_SPLAY, H_TOWER,
                  74.0, 46.0, 50.0, 34.0, 18, band0=1)
        # stacked horizontal crossarms — longer low, shorter high (candelabra look)
        n_arms = 6
        for k in range(n_arms):
            t = k / float(n_arms - 1)
            z = lerp(H_SPLAY + 30, H_TOWER - 20, t)
            crossarm(feats, b, R_ANT, z, lerp(150.0, 58.0, t), 11.0,
                     band(k, offset=1))
        # slender mast: taper through several segments to a thin needle tip
        leg_stack(feats, b, R_ANT, R_ANT, H_TOWER, tip - 60,
                  40.0, 9.0, 30.0, 8.0, 10, band0=2)
        cx, cy = leg_xy(b, R_ANT)
        feats.append(feat(rect(cx, cy, 8, 7, b + 90), tip - 60, tip, ORANGE))

    # --- crown crossarms linking the three antenna towers at the top ---
    for i in range(3):
        x1, y1 = leg_xy(LEGS[i], R_ANT)
        x2, y2 = leg_xy(LEGS[(i + 1) % 3], R_ANT)
        mx, my = (x1 + x2) / 2.0, (y1 + y2) / 2.0
        length = math.hypot(x2 - x1, y2 - y1)
        rot = math.degrees(math.atan2(y2 - y1, x2 - x1))
        feats.append(feat(rect(mx, my, length, 22, rot), H_TOWER - 40, H_TOWER, ORANGE))

    with open(OUT, "w") as fh:
        json.dump({"type": "FeatureCollection", "features": feats}, fh)
    print("wrote %s (%d pieces)" % (OUT, len(feats)))


if __name__ == "__main__":
    main()
