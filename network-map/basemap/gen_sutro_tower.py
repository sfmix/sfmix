#!/usr/bin/env python3
"""Generate the (comically large) 3D Sutro Tower.

Writes website/static/map/sutro.json: a FeatureCollection of polygon pieces
with {base, height, color} properties that network-map.js draws as a
fill-extrusion layer. The tower is stylized from vertical prisms — three
tapered-looking legs (via stacked, narrowing segments), the waist deck, the
three upper masts and the candelabra crossarms — painted in night-muted
international orange + white bands like the real thing. Scale is ~5x real
(1.5 km tall) per operator taste: visible from across the bay when pitched.

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


def main():
    feats = []
    legs = [90, 210, 330]  # bearings of the three legs (degrees, math convention)
    R = 260.0              # leg-circle radius (m)

    for b in legs:
        r = math.radians(b)
        cx, cy = R * math.cos(r), R * math.sin(r)
        rot = b + 90  # long face tangential, so legs read as blades like the real ones
        # stacked, narrowing segments fake the inward taper + paint the bands
        feats.append(feat(rect(cx, cy, 150, 90, rot), 0, 420, ORANGE))
        feats.append(feat(rect(cx, cy, 130, 80, rot), 420, 620, WHITE))
        feats.append(feat(rect(cx, cy, 110, 70, rot), 620, 980, ORANGE))
        # upper mast above each leg
        feats.append(feat(rect(cx, cy, 70, 55, rot), 980, 1380, ORANGE))
        feats.append(feat(rect(cx, cy, 55, 45, rot), 1380, 1520, WHITE))

    # waist deck: triangle through the three legs
    ring = [[round(CENTER[0] + R * math.cos(math.radians(b)) * M_LON, 6),
             round(CENTER[1] + R * math.sin(math.radians(b)) * M_LAT, 6)]
            for b in legs]
    ring.append(ring[0])
    feats.append(feat([ring], 920, 990, WHITE))

    # candelabra crossarms linking the mast tops pairwise
    for i in range(3):
        b1, b2 = math.radians(legs[i]), math.radians(legs[(i + 1) % 3])
        x1, y1 = R * math.cos(b1), R * math.sin(b1)
        x2, y2 = R * math.cos(b2), R * math.sin(b2)
        mx, my = (x1 + x2) / 2.0, (y1 + y2) / 2.0
        length = math.hypot(x2 - x1, y2 - y1)
        rot = math.degrees(math.atan2(y2 - y1, x2 - x1))
        feats.append(feat(rect(mx, my, length, 30, rot), 1420, 1460, ORANGE))

    with open(OUT, "w") as fh:
        json.dump({"type": "FeatureCollection", "features": feats}, fh)
    print("wrote %s (%d pieces)" % (OUT, len(feats)))


if __name__ == "__main__":
    main()
