#!/usr/bin/env python3
"""Generate the SFMIX Snappy hero skyline SVG (viewBox 2400x220) and splice it into
ansible/roles/snappy/templates/landing-page.html.j2 between <div class="hero"> and
<div class="container">.  Deterministic (seeded), so re-running is a no-op unless edited.

    python3 ansible/roles/snappy/files/gen_skyline.py ansible/roles/snappy/templates/landing-page.html.j2
"""
import random, sys

random.seed(40271)
W, H = 2400, 220
GROUND = 200            # waterfront / building baseline
out = []
def e(s): out.append(s)

def qbez(p0, p1, p2, t):
    return ((1-t)**2*p0[0] + 2*t*(1-t)*p1[0] + t*t*p2[0],
            (1-t)**2*p0[1] + 2*t*(1-t)*p1[1] + t*t*p2[1])
def cbez(p0, p1, p2, p3, t):
    mt = 1-t
    return (mt**3*p0[0] + 3*mt*mt*t*p1[0] + 3*mt*t*t*p2[0] + t**3*p3[0],
            mt**3*p0[1] + 3*mt*mt*t*p1[1] + 3*mt*t*t*p2[1] + t**3*p3[1])

CROWN_CYCLE = 'values="#ffc178;#8ec5ff;#ff8bd6;#9dffc9;#ffc178" dur="18s" repeatCount="indefinite"'

e('<svg viewBox="0 0 2400 220" preserveAspectRatio="xMidYMax slice" xmlns="http://www.w3.org/2000/svg" aria-hidden="true" focusable="false">')
e('<defs>')
e('  <linearGradient id="waterGrad" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#0b1424"/><stop offset="1" stop-color="#0d1117"/></linearGradient>')
e('  <radialGradient id="cityGlow" cx="0.5" cy="1" r="0.6"><stop offset="0" stop-color="#ffb46b" stop-opacity="0.16"/><stop offset="1" stop-color="#ffb46b" stop-opacity="0"/></radialGradient>')
e('  <radialGradient id="moonGlow"><stop offset="0" stop-color="#fff6d8" stop-opacity="0.35"/><stop offset="1" stop-color="#fff6d8" stop-opacity="0"/></radialGradient>')
e('  <linearGradient id="crownGrad" x1="0" y1="0" x2="0" y2="1">')
e(f'    <stop offset="0" stop-color="#ffc178" stop-opacity="0.95"><animate attributeName="stop-color" {CROWN_CYCLE}/></stop>')
e(f'    <stop offset="1" stop-color="#ffc178" stop-opacity="0"><animate attributeName="stop-color" {CROWN_CYCLE}/></stop>')
e('  </linearGradient>')
e(f'  <radialGradient id="crownHalo"><stop offset="0" stop-color="#ffc178" stop-opacity="0.45"><animate attributeName="stop-color" {CROWN_CYCLE}/></stop><stop offset="1" stop-color="#ffc178" stop-opacity="0"><animate attributeName="stop-color" {CROWN_CYCLE}/></stop></radialGradient>')
e('  <linearGradient id="reflect" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#ffffff" stop-opacity="0.28"/><stop offset="1" stop-color="#ffffff" stop-opacity="0"/></linearGradient>')
e('  <linearGradient id="reflectOrange" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#e0603f" stop-opacity="0.35"/><stop offset="1" stop-color="#e0603f" stop-opacity="0"/></linearGradient>')
e(f'  <linearGradient id="reflectCrown" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#ffc178" stop-opacity="0.5"><animate attributeName="stop-color" {CROWN_CYCLE}/></stop><stop offset="1" stop-color="#ffc178" stop-opacity="0"/></linearGradient>')
e('  <filter id="fogBlur" x="-10%" y="-50%" width="120%" height="200%"><feGaussianBlur stdDeviation="7 3"/></filter>')
e('  <filter id="softGlow" x="-50%" y="-50%" width="200%" height="200%"><feGaussianBlur stdDeviation="3"/></filter>')
e('  <filter id="reflBlur" x="-20%" y="-20%" width="140%" height="140%"><feGaussianBlur stdDeviation="1.5 0.6"/></filter>')
# window patterns: three phases so adjacent towers don't line up
e('  <pattern id="winA" width="7" height="10" patternUnits="userSpaceOnUse"><rect x="1.5" y="2" width="2.4" height="3.6" fill="#ffd68a" opacity="0.55"/></pattern>')
e('  <pattern id="winB" width="8" height="11" patternUnits="userSpaceOnUse" patternTransform="translate(3 4)"><rect x="1" y="2" width="2.6" height="3.8" fill="#bcd9ff" opacity="0.42"/></pattern>')
e('  <pattern id="winC" width="6" height="9" patternUnits="userSpaceOnUse" patternTransform="translate(1 6)"><rect x="1" y="1.5" width="2" height="3" fill="#ffe7b0" opacity="0.3"/></pattern>')
e('  <mask id="moonMask"><rect x="1920" y="10" width="80" height="80" fill="white"/><circle cx="1967" cy="40" r="12.5" fill="black"/></mask>')
SF = 'M1262,200 L1262,62 Q1262,26 1282,26 Q1302,26 1302,62 L1302,200 Z'
e(f'  <clipPath id="sfClip"><path d="{SF}"/></clipPath>')
e('</defs>')

# ---------- Stars ----------
e('<!-- Stars -->')
e('<g class="stars">')
for _ in range(64):
    x = random.uniform(0, W); y = random.uniform(4, 120)
    if 1900 < x < 2030 and y < 90: continue          # keep the moon clear
    r = random.choice([0.6, 0.8, 0.9, 1.1, 1.3])
    dur = random.uniform(2.2, 6.5); beg = random.uniform(0, 6)
    lo = random.uniform(0.15, 0.35); hi = random.uniform(0.7, 1.0)
    e(f'  <circle cx="{x:.0f}" cy="{y:.0f}" r="{r}" fill="#e6ecff"><animate attributeName="opacity" values="{lo:.2f};{hi:.2f};{lo:.2f}" dur="{dur:.1f}s" begin="{beg:.1f}s" repeatCount="indefinite"/></circle>')
e('</g>')

# ---------- Moon ----------
e('<!-- Crescent moon over the East Bay -->')
e('<circle cx="1960" cy="45" r="34" fill="url(#moonGlow)"/>')
e('<circle cx="1960" cy="45" r="14" fill="#efe9d2" mask="url(#moonMask)"/>')

# ---------- Far hills ----------
e('<!-- Marin Headlands (left) and East Bay hills (right), far layer -->')
e(f'<path d="M0,{GROUND} L0,150 C60,130 120,118 190,124 C260,130 300,112 370,120 C430,128 470,150 520,{GROUND} Z" fill="#161d2c"/>')
e(f'<path d="M1880,{GROUND} L1880,186 C1960,176 2060,172 2160,176 C2260,180 2340,172 2400,178 L2400,{GROUND} Z" fill="#161d2c"/>')

# ---------- Downtown glow ----------
e('<ellipse cx="1280" cy="200" rx="420" ry="150" fill="url(#cityGlow)"/>')

# ---------- Golden Gate Bridge ----------
GG = '#c9482f'; GGD = '#a63a26'
T1, T2 = 620, 840; TOP = 68; DECK = 164
e('<!-- Golden Gate Bridge -->')
e('<g class="golden-gate">')
A0 = (470, DECK-2); A1 = (990, DECK-2)
c_left  = (A0, (540, 80), (585, TOP), (T1, TOP))
c_mid   = ((T1, TOP), (730, 192), (T2, TOP))
c_right = ((T2, TOP), (875, TOP), (920, 80), A1)
e(f'  <path d="M{A0[0]},{A0[1]} C540,80 585,{TOP} {T1},{TOP} Q730,192 {T2},{TOP} C875,{TOP} 920,80 {A1[0]},{A1[1]}" stroke="{GG}" stroke-width="2.4" fill="none" stroke-linecap="round"/>')
sus = []
for i in range(1, 16):
    sus.append(cbez(*c_left, i/16))
for i in range(1, 16):
    sus.append(qbez(*c_mid, i/16))
for i in range(1, 16):
    sus.append(cbez(*c_right, i/16))
for (x, y) in sus:
    if y < DECK - 2:
        e(f'  <line x1="{x:.1f}" y1="{y:.1f}" x2="{x:.1f}" y2="{DECK}" stroke="{GG}" stroke-width="0.7" opacity="0.8"/>')
for tx in (T1, T2):
    e(f'  <rect x="{tx-10}" y="{TOP-2}" width="6" height="{GROUND-(TOP-2)}" fill="{GG}"/>')
    e(f'  <rect x="{tx+4}" y="{TOP-2}" width="6" height="{GROUND-(TOP-2)}" fill="{GG}"/>')
    for sy in (TOP-2, 84, 104, 126, 148):
        e(f'  <rect x="{tx-10}" y="{sy}" width="20" height="4" fill="{GGD}"/>')
    e(f'  <circle cx="{tx}" cy="{TOP-4}" r="1.4" fill="#ff5a4a"><animate attributeName="opacity" values="1;0.15;1" dur="2.4s" begin="{(tx-T1)/220*1.2:.1f}s" repeatCount="indefinite"/></circle>')
e(f'  <rect x="470" y="{DECK}" width="520" height="4" fill="{GGD}"/>')
e(f'  <rect x="470" y="{DECK+4}" width="520" height="1.2" fill="#1a1f2b" opacity="0.6"/>')
# headlights / taillights along the deck
e(f'  <circle r="1.4" fill="#fff1c1" opacity="0.9"><animateMotion path="M470,{DECK-1.5} L990,{DECK-1.5}" dur="11s" repeatCount="indefinite"/></circle>')
e(f'  <circle r="1.4" fill="#fff1c1" opacity="0.9"><animateMotion path="M470,{DECK-1.5} L990,{DECK-1.5}" dur="11s" begin="4.5s" repeatCount="indefinite"/></circle>')
e(f'  <circle r="1.3" fill="#ff6b5a" opacity="0.9"><animateMotion path="M990,{DECK-1.5} L470,{DECK-1.5}" dur="13s" begin="1.5s" repeatCount="indefinite"/></circle>')
e(f'  <circle r="1.3" fill="#ff6b5a" opacity="0.9"><animateMotion path="M990,{DECK-1.5} L470,{DECK-1.5}" dur="13s" begin="8s" repeatCount="indefinite"/></circle>')
e('</g>')

# ---------- Twin Peaks + Sutro Tower ----------
S = 985; SUT = '#6e3838'
e('<!-- Twin Peaks with Sutro Tower -->')
e(f'<path d="M860,{GROUND} C900,175 940,152 985,150 C1030,152 1060,168 1100,178 C1130,185 1160,192 1190,{GROUND} Z" fill="#1b2434"/>')
e('<g class="sutro">')
e(f'  <path d="M{S-9},150 L{S-6},150 {S-3},94 {S-4.5},94 Z" fill="{SUT}"/>')
e(f'  <path d="M{S+9},150 L{S+6},150 {S+3},94 {S+4.5},94 Z" fill="{SUT}"/>')
for sy, half in ((140, 7), (126, 6), (112, 5)):
    e(f'  <line x1="{S-half}" y1="{sy}" x2="{S+half}" y2="{sy}" stroke="{SUT}" stroke-width="1.1"/>')
e(f'  <rect x="{S-6}" y="92" width="12" height="2.5" fill="{SUT}"/>')
e(f'  <rect x="{S-1}" y="46" width="2" height="46" fill="{SUT}"/>')
e(f'  <path d="M{S-4},92 L{S-6},56 {S-5},56 {S-3},92 Z" fill="{SUT}"/>')
e(f'  <path d="M{S+4},92 L{S+6},56 {S+5},56 {S+3},92 Z" fill="{SUT}"/>')
e(f'  <line x1="{S-5.5}" y1="56" x2="{S-5.5}" y2="50" stroke="{SUT}" stroke-width="1"/>')
e(f'  <line x1="{S+5.5}" y1="56" x2="{S+5.5}" y2="50" stroke="{SUT}" stroke-width="1"/>')
e(f'  <circle cx="{S}" cy="45" r="1.7" fill="#ff3b30"><animate attributeName="opacity" values="1;1;0.05;0.05;1" keyTimes="0;0.45;0.5;0.95;1" dur="1.6s" repeatCount="indefinite"/></circle>')
e(f'  <circle cx="{S-5.5}" cy="49" r="1" fill="#ff3b30"><animate attributeName="opacity" values="0.1;1;0.1" dur="1.6s" begin="0.4s" repeatCount="indefinite"/></circle>')
e(f'  <circle cx="{S+5.5}" cy="49" r="1" fill="#ff3b30"><animate attributeName="opacity" values="0.1;1;0.1" dur="1.6s" begin="1.1s" repeatCount="indefinite"/></circle>')
e('</g>')

# ---------- Downtown ----------
e('<!-- Downtown: Telegraph Hill / Coit, Transamerica, 555 California, Salesforce Tower, 181 Fremont, Millennium, Ferry Building -->')
e(f'<path d="M1000,{GROUND} L1000,182 1030,182 1030,176 1044,176 C1064,168 1084,172 1104,176 L1120,176 1120,184 1150,184 1150,180 1180,180 1180,186 1205,186 1205,178 1240,178 1240,184 1265,184 1265,180 1300,180 1300,186 1330,186 1330,182 1360,182 1360,188 1395,188 1395,183 1420,183 1420,190 1460,190 1460,186 1480,186 1480,192 1540,192 1540,{GROUND} Z" fill="#1a2231"/>')
# Coit Tower
e('<path d="M1075,176 L1076,132 1075,130 1075,128 1087,128 1087,130 1086,132 1087,176 Z" fill="#2d374b"/>')
e('<rect x="1077" y="130" width="8" height="3" fill="url(#winC)"/>')
def tower(shape_attrs, fill, win=None):
    e(f'<{shape_attrs} fill="{fill}"/>')
    if win: e(f'<{shape_attrs} fill="url(#{win})"/>')
tower('rect x="1230" y="128" width="28" height="72"', '#1f2839', 'winB')
tower('rect x="1190" y="94" width="34" height="106"', '#1c2436', 'winA')
e('<path d="M1190,94 L1193,90 1197,94 1201,90 1205,94 1209,90 1213,94 1217,90 1221,94 1224,94" fill="#1c2436"/>')
# Transamerica Pyramid
tower('polygon points="1150,42 1128,200 1172,200"', '#242e42', 'winC')
e('<rect x="1137" y="72" width="3" height="34" fill="#2c3750"/>')
e('<rect x="1160" y="72" width="3" height="34" fill="#2c3750"/>')
e('<circle cx="1150" cy="42" r="6" fill="#fff3c4" opacity="0.35" filter="url(#softGlow)"><animate attributeName="opacity" values="0.15;0.5;0.15" dur="3s" repeatCount="indefinite"/></circle>')
e('<circle cx="1150" cy="42" r="1.6" fill="#fff8dc"><animate attributeName="opacity" values="0.6;1;0.6" dur="3s" repeatCount="indefinite"/></circle>')
# Salesforce Tower with its crown
e('<ellipse cx="1282" cy="40" rx="42" ry="30" fill="url(#crownHalo)"><animate attributeName="ry" values="30;36;30" dur="6s" repeatCount="indefinite"/></ellipse>')
tower(f'path d="{SF}"', '#2a3448', 'winB')
e('<rect x="1262" y="26" width="40" height="40" fill="url(#crownGrad)" clip-path="url(#sfClip)"><animate attributeName="opacity" values="0.75;1;0.75" dur="6s" repeatCount="indefinite"/></rect>')
# 181 Fremont
tower('rect x="1322" y="72" width="20" height="128"', '#232d42', 'winA')
e('<line x1="1332" y1="72" x2="1332" y2="50" stroke="#3a4560" stroke-width="1.4"/>')
e('<circle cx="1332" cy="50" r="1" fill="#ff5a4a"><animate attributeName="opacity" values="1;0.1;1" dur="2s" begin="0.7s" repeatCount="indefinite"/></circle>')
# Millennium + misc
tower('rect x="1350" y="104" width="26" height="96"', '#1e2738', 'winC')
tower('rect x="1385" y="118" width="22" height="82"', '#212b3d', 'winB')
tower('path d="M1412,200 L1412,148 1426,148 1426,140 1440,140 1440,200 Z"', '#1c2535', 'winA')
tower('rect x="1448" y="158" width="22" height="42"', '#1f2839', 'winC')
tower('rect x="1100" y="150" width="18" height="50"', '#1f2839', 'winB')
# Ferry Building
e('<rect x="1478" y="178" width="46" height="22" fill="#2a3244"/>')
e('<rect x="1494" y="134" width="14" height="46" fill="#333c50"/>')
e('<polygon points="1494,134 1501,126 1508,134" fill="#333c50"/>')
e('<circle cx="1501" cy="148" r="4.2" fill="#f6ecd0"/>')
e('<line x1="1501" y1="148" x2="1501" y2="145" stroke="#333c50" stroke-width="0.8"/>')
e('<line x1="1501" y1="148" x2="1503.5" y2="149.5" stroke="#333c50" stroke-width="0.8"/>')
e('<rect x="1480" y="182" width="42" height="14" fill="url(#winA)"/>')
# flickering windows
e('<g class="flicker">')
flick = [(1195,120),(1210,150),(1270,90),(1290,130),(1240,150),(1330,110),(1336,160),(1358,140),(1392,150),(1146,120),(1152,160),(1418,170),(1455,175),(1105,170)]
for (x, y) in flick:
    d = random.uniform(1.8, 5.0); b = random.uniform(0, 4)
    e(f'  <rect x="{x}" y="{y}" width="2.4" height="3.6" fill="#fff0c0"><animate attributeName="opacity" values="0.1;0.95;0.1" dur="{d:.1f}s" begin="{b:.1f}s" repeatCount="indefinite"/></rect>')
e('</g>')

# ---------- Bay Bridge (west suspension spans) ----------
BB = '#5b6880'; BBC = '#8a97ad'
B1, B2 = 1580, 1780; BTOP = 84; BDECK = 168
e('<!-- Bay Bridge west spans with the Bay Lights -->')
e('<g class="bay-bridge">')
b_left  = ((1500, BDECK-2), (1545, 100), (1560, BTOP), (B1, BTOP))
b_mid   = ((B1, BTOP), (1680, 204), (B2, BTOP))
b_right = ((B2, BTOP), (1800, BTOP), (1815, 100), (1880, BDECK-2))
e(f'  <path d="M1500,{BDECK-2} C1545,100 1560,{BTOP} {B1},{BTOP} Q1680,204 {B2},{BTOP} C1800,{BTOP} 1815,100 1880,{BDECK-2}" stroke="{BBC}" stroke-width="2" fill="none"/>')
bsus = []
for i in range(1, 13):
    bsus.append(cbez(*b_left, i/13))
for i in range(1, 17):
    bsus.append(qbez(*b_mid, i/17))
for i in range(1, 13):
    bsus.append(cbez(*b_right, i/13))
lights = []
for (x, y) in bsus:
    if y < BDECK - 3:
        e(f'  <line x1="{x:.1f}" y1="{y:.1f}" x2="{x:.1f}" y2="{BDECK}" stroke="{BB}" stroke-width="0.7"/>')
        n = max(1, int((BDECK - y) / 9))
        for k in range(n):
            ly = y + (k + 0.5) * (BDECK - y) / n + random.uniform(-2, 2)
            lights.append((x, ly))
for tx in (B1, B2):
    e(f'  <rect x="{tx-9}" y="{BTOP-2}" width="5" height="{GROUND-(BTOP-2)}" fill="{BB}"/>')
    e(f'  <rect x="{tx+4}" y="{BTOP-2}" width="5" height="{GROUND-(BTOP-2)}" fill="{BB}"/>')
    for sy in (BTOP-2, 96, 120, 145):
        e(f'  <rect x="{tx-9}" y="{sy}" width="18" height="3.5" fill="#46536a"/>')
    e(f'  <line x1="{tx-6}" y1="100" x2="{tx+6}" y2="120" stroke="#46536a" stroke-width="1"/>')
    e(f'  <line x1="{tx+6}" y1="100" x2="{tx-6}" y2="120" stroke="#46536a" stroke-width="1"/>')
    e(f'  <line x1="{tx-6}" y1="124" x2="{tx+6}" y2="145" stroke="#46536a" stroke-width="1"/>')
    e(f'  <line x1="{tx+6}" y1="124" x2="{tx-6}" y2="145" stroke="#46536a" stroke-width="1"/>')
    e(f'  <circle cx="{tx}" cy="{BTOP-4}" r="1.3" fill="#ff5a4a"><animate attributeName="opacity" values="1;0.15;1" dur="2.8s" begin="{(tx-B1)/200*1.4:.1f}s" repeatCount="indefinite"/></circle>')
e(f'  <rect x="1500" y="{BDECK}" width="380" height="4" fill="#3d4a60"/>')
e(f'  <rect x="1500" y="{BDECK+4}" width="380" height="1.2" fill="#0f141d" opacity="0.7"/>')
e(f'  <circle r="1.3" fill="#fff1c1" opacity="0.9"><animateMotion path="M1500,{BDECK-1.5} L1880,{BDECK-1.5}" dur="9s" repeatCount="indefinite"/></circle>')
e(f'  <circle r="1.2" fill="#ff6b5a" opacity="0.9"><animateMotion path="M1880,{BDECK-1.5} L1500,{BDECK-1.5}" dur="10s" begin="3s" repeatCount="indefinite"/></circle>')
e('  <g class="bay-lights">')
for (x, y) in lights:
    d = random.uniform(1.6, 4.2); b = random.uniform(0, 4); lo = random.uniform(0.05, 0.25)
    e(f'    <circle cx="{x:.1f}" cy="{y:.1f}" r="0.85" fill="#ffffff"><animate attributeName="opacity" values="{lo:.2f};1;{lo:.2f}" dur="{d:.1f}s" begin="{b:.1f}s" repeatCount="indefinite"/></circle>')
e('  </g>')
e('</g>')

# ---------- Yerba Buena Island + east span SAS tower ----------
e('<!-- Yerba Buena Island and the east span self-anchored suspension tower -->')
e(f'<path d="M1850,{GROUND} C1880,168 1910,152 1950,150 C1990,152 2010,170 2040,{GROUND} Z" fill="#1a2232"/>')
e('<g class="east-span">')
E = 2110; ETOP = 60; EDECK = 170
e(f'  <path d="M2000,{EDECK-2} Q2040,{ETOP} {E},{ETOP} Q2180,{ETOP} 2220,{EDECK-2}" stroke="#8f9bb0" stroke-width="1.2" fill="none"/>')
for i in range(1, 12):
    x, y = qbez((2000, EDECK-2), (2040, ETOP), (E, ETOP), i/12)
    e(f'  <line x1="{x:.1f}" y1="{y:.1f}" x2="{x:.1f}" y2="{EDECK}" stroke="#6f7a8f" stroke-width="0.6"/>')
    x, y = qbez((E, ETOP), (2180, ETOP), (2220, EDECK-2), i/12)
    e(f'  <line x1="{x:.1f}" y1="{y:.1f}" x2="{x:.1f}" y2="{EDECK}" stroke="#6f7a8f" stroke-width="0.6"/>')
e(f'  <rect x="{E-3.5}" y="{ETOP-2}" width="7" height="{GROUND-(ETOP-2)}" fill="#a3adbf"/>')
e(f'  <circle cx="{E}" cy="{ETOP-4}" r="1.2" fill="#ff5a4a"><animate attributeName="opacity" values="1;0.15;1" dur="2.2s" begin="0.9s" repeatCount="indefinite"/></circle>')
e(f'  <rect x="2030" y="{EDECK}" width="370" height="4" fill="#4a5568"/>')
e(f'  <line x1="2030" y1="{EDECK-1}" x2="2400" y2="{EDECK-1}" stroke="#ffffff" stroke-width="1" stroke-dasharray="1 11" opacity="0.55"/>')
e('</g>')

# ---------- Water + reflections ----------
e('<!-- The Bay -->')
e(f'<rect x="0" y="{GROUND}" width="{W}" height="{H-GROUND}" fill="url(#waterGrad)"/>')
e('<g filter="url(#reflBlur)" opacity="0.9">')
e(f'  <rect x="{T1-12}" y="{GROUND}" width="24" height="18" fill="url(#reflectOrange)"/>')
e(f'  <rect x="{T2-12}" y="{GROUND}" width="24" height="18" fill="url(#reflectOrange)"/>')
e(f'  <rect x="1268" y="{GROUND}" width="28" height="20" fill="url(#reflectCrown)"><animate attributeName="x" values="1268;1266;1270;1268" dur="7s" repeatCount="indefinite"/></rect>')
e(f'  <rect x="{B1-10}" y="{GROUND}" width="20" height="16" fill="url(#reflect)"/>')
e(f'  <rect x="{B2-10}" y="{GROUND}" width="20" height="16" fill="url(#reflect)"/>')
e(f'  <rect x="{E-6}" y="{GROUND}" width="12" height="18" fill="url(#reflect)"/>')
e(f'  <rect x="1140" y="{GROUND}" width="20" height="12" fill="url(#reflect)" opacity="0.5"/>')
e('</g>')
e('<g class="shimmer" opacity="0.35">')
for i, y in enumerate((204, 208, 213, 217)):
    e(f'  <line x1="0" y1="{y}" x2="{W}" y2="{y}" stroke="#ffffff" stroke-width="0.6" stroke-dasharray="{random.randint(8,20)} {random.randint(30,60)}" opacity="{0.35 - i*0.06:.2f}"><animate attributeName="stroke-dashoffset" from="0" to="{-90 if i%2 else 90}" dur="{9 + i*2}s" repeatCount="indefinite"/></line>')
e('</g>')

# ---------- Fog ----------
e('<!-- Karl the Fog: pouring through the Gate, rolling over the hills, wisping around the towers -->')
e('<g filter="url(#fogBlur)">')
e('  <path d="M300,168 C420,150 520,158 640,150 C760,142 860,160 1000,154 C1100,150 1140,164 1200,164 L1200,184 C1100,186 1000,176 860,180 C760,184 640,172 520,178 C420,184 340,178 300,186 Z" fill="white" opacity="0.10"><animateTransform attributeName="transform" type="translate" values="-60,0;90,3;-60,0" dur="22s" repeatCount="indefinite"/></path>')
e('  <path d="M-200,176 C0,170 200,178 420,172 C640,166 760,176 980,170 C1200,164 1320,176 1560,172 C1800,168 2000,178 2200,174 L2600,178 L2600,200 L-200,200 Z" fill="white" opacity="0.07"><animateTransform attributeName="transform" type="translate" values="0,0;80,2;-60,-1;0,0" dur="26s" repeatCount="indefinite"/></path>')
e('  <path d="M-100,160 C120,154 260,164 480,156 C700,148 820,160 1040,154 C1260,148 1400,158 1640,152 C1880,146 2060,158 2300,154 L2500,160 L2500,172 L-100,172 Z" fill="white" opacity="0.05"><animateTransform attributeName="transform" type="translate" values="0,0;-70,1;50,-1;0,0" dur="34s" repeatCount="indefinite"/></path>')
e('  <path d="M1020,120 C1120,114 1200,124 1300,118 C1400,112 1470,120 1560,116 L1560,128 C1470,132 1400,124 1300,130 C1200,136 1120,128 1020,134 Z" fill="white" opacity="0.045"><animateTransform attributeName="transform" type="translate" values="0,0;50,-2;-70,1;0,0" dur="30s" repeatCount="indefinite"/></path>')
e('  <path d="M560,140 C640,134 720,144 800,138 C880,132 940,142 1000,136 L1000,150 C940,156 880,146 800,152 C720,158 640,148 560,154 Z" fill="white" opacity="0.08"><animateTransform attributeName="transform" type="translate" values="0,0;-45,2;60,-1;0,0" dur="16s" repeatCount="indefinite"/></path>')
e('</g>')
e('</svg>')

svg = '\n'.join(out)

# ---------- Splice ----------
path = sys.argv[1]
src = open(path).read()
start = src.index('    <div class="hero">')
end = src.index('    <div class="container">')
fibers = ''.join('        <div class="fiber"></div>\n' for _ in range(10))
hero = ('    <div class="hero">\n' + fibers +
        '        <div class="skyline">\n' +
        '\n'.join('            ' + l for l in svg.splitlines()) + '\n' +
        '        </div>\n    </div>\n')
src = src[:start] + hero + src[end:]
open(path, 'w').write(src)
print(f"svg bytes: {len(svg)}, elements: {svg.count('<')}")
