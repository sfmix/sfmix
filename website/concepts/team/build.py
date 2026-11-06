#!/usr/bin/env python3
"""Build the /team/ page concepts: wrap each fragment in the real sfmix.org shell.

Usage: build.py SITE_DIR OUT_DIR
  SITE_DIR  a `hugo` build of website/ (its team/index.html is the shell)
  OUT_DIR   where to write index.html, one HTML per concept, src/ and site/

The output is self-contained (relative paths), so it works from file:// or
under any URL prefix, e.g. www-staging.sfmix.org/team-concepts/.
"""
import re
import shutil
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent

PAGES = [
    # (output, fragment, <title>)
    ("index.html", "index.frag.html", "Team page concepts"),
    ("a-faces.html", "a-faces.frag.html", "Concept A: everyone at a glance"),
    ("b-matrix.html", "b-matrix.frag.html", "Concept B: who does what"),
    ("c-ops-first.html", "c-ops-first.frag.html", "Concept C: operations first"),
]
NAV = [("index.html", "Overview"), ("a-faces.html", "A. Everyone at a glance"),
       ("b-matrix.html", "B. Who does what"), ("c-ops-first.html", "C. Operations first")]
ASSET_PREFIXES = ("/css/", "/fonts/", "/img/", "/video/", "/favicon")


def rewrite(html):
    def attr(m):
        q, path = m.group(1), m.group(2)
        if path.startswith(ASSET_PREFIXES):
            return f"{q}site{path}"
        return f"{q}https://sfmix.org{path}"
    html = re.sub(r'(="|=\')(/(?!/)[^"\']*)', attr, html)
    html = html.replace("url('/", "url('site/")
    # No language auto-redirect (it would jump out of the concepts).
    html = re.sub(r"var translations = .*?;\n", "var translations = {};\n", html)
    return html


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    src, out = Path(sys.argv[1]), Path(sys.argv[2])
    out.mkdir(parents=True, exist_ok=True)

    team = (src / "team/index.html").read_text()
    head, rest = team.split('<div class="content">', 1)
    foot = "  </main>" + rest.split("  </main>", 1)[1]
    head = rewrite(head).replace(
        '<link rel="stylesheet" href="site/css/style.css">',
        '<link rel="stylesheet" href="site/css/style.css">\n  <link rel="stylesheet" href="src/common.css">')
    head = re.sub(r'\s*<link rel="manifest"[^>]*>', "", head)
    foot = rewrite(foot)

    # Assets
    dst = out / "site"
    for sub in ("fonts", "img/team"):
        shutil.copytree(src / sub, dst / sub, dirs_exist_ok=True)
    for f in ("img/sfmix-logo-large.png", "img/favicon.svg", "img/mobile-golden-gate.jpg",
              "video/team-bg.mp4", "favicon.ico"):
        (dst / f).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src / f, dst / f)
    css = (src / "css/style.css").read_text().replace("url('/", "url('../").replace('url("/', 'url("../')
    (dst / "css").mkdir(parents=True, exist_ok=True)
    (dst / "css/style.css").write_text(css)
    (out / "src").mkdir(exist_ok=True)
    for f in ("people.js", "common.js", "common.css"):
        shutil.copy2(HERE / "src" / f, out / "src" / f)

    for page, frag, title in PAGES:
        nav = '<nav class="concepts" aria-label="Design concepts"><strong>Concepts</strong>' + "".join(
            '<a href="%s"%s>%s</a>' % (href, ' aria-current="page"' if href == page else "", label)
            for href, label in NAV) + "</nav>"
        body = (HERE / "src" / frag).read_text()
        html = re.sub(r"<title>.*?</title>", f"<title>{title} | SFMIX</title>", head)
        html += ('<div class="content">\n  <div class="container">\n' + nav +
                 '\n<script src="src/people.js"></script>\n<script src="src/common.js"></script>\n' +
                 body + "\n  </div>\n</div>\n" + foot)
        (out / page).write_text(html)
    print(f"team concepts -> {out}")


if __name__ == "__main__":
    main()
