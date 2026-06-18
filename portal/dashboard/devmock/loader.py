"""Convention-based fixture loader + client monkeypatch.

The mapping from an API path to a fixture file is purely mechanical, so any new
client method that calls ``_get("/api/v1/<thing>")`` is served automatically the
moment a matching JSON file exists under ``fixtures/<source>/`` — the loader
never needs editing to support new endpoints.

Naming convention (see :func:`fixture_candidates`):

    /api/v1/interfaces/status            -> interfaces_status.json
    /api/v1/interfaces/status  ?asn=64496 -> interfaces_status__asn-64496.json
                                            (falls back to interfaces_status.json)
    /api/v1/participants/64496           -> participants_64496.json
    /api/v1/routeservers/rs1/neighbors   -> routeservers_rs1_neighbors.json
"""

import json
import logging
from pathlib import Path

from django.conf import settings

logger = logging.getLogger(__name__)

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"

# Endpoints whose real response is a JSON object rather than a list. Used only
# to pick the right empty container when a fixture is missing, so a gap degrades
# to an empty page instead of a 500.
_DICT_ENDPOINTS = ("participants/", "netbox/status", "peeringdb-cache", "discovered-neighbors", "routeservers")


def _normalize(path):
    """Strip the API prefix and turn the path into a filename stem."""
    p = path.strip("/")
    for prefix in ("api/v1/", "api/"):
        if p.startswith(prefix):
            p = p[len(prefix):]
            break
    return p.replace("/", "_")


def fixture_candidates(path, params):
    """Ordered fixture filenames for (path, params), most specific first."""
    stem = _normalize(path)
    candidates = []
    if params:
        suffix = "__" + "_".join(f"{k}-{params[k]}" for k in sorted(params))
        candidates.append(f"{stem}{suffix}.json")
    candidates.append(f"{stem}.json")
    return candidates


def _empty_for(path):
    """Empty container matching the endpoint's expected shape."""
    return {} if any(s in path for s in _DICT_ENDPOINTS) else []


def load(subdir, path, params=None):
    """Return parsed JSON for (path, params), or a logged empty fallback."""
    base = FIXTURES_DIR / subdir
    tried = fixture_candidates(path, params)
    for name in tried:
        fpath = base / name
        if fpath.exists():
            with fpath.open() as fh:
                return json.load(fh)
    logger.warning(
        "[devmock] no fixture for %s (params=%s) — looked for: %s. "
        "Create fixtures/%s/%s to populate this endpoint.",
        path, params, ", ".join(tried), subdir, tried[0],
    )
    return _empty_for(path)


def _make_get(subdir):
    """Build a ``_get`` replacement bound to a fixtures subdir.

    Matches both client signatures: LookingGlassClient._get(path, token, params)
    and AliceLGClient._get(path).
    """
    def _get(self, path, token=None, params=None):
        return load(subdir, path, params)
    return _get


# (client_class_path, fixtures_subdir). Add a row here to mock a new data
# source — nothing else in the loader changes.
_CLIENTS = [
    ("dashboard.lg_client", "LookingGlassClient", "lg"),
    ("dashboard.alice_client", "AliceLGClient", "alice"),
]


def install():
    """Patch each client's ``_get`` to read fixtures. DEBUG-only, idempotent."""
    if not settings.DEBUG:  # belt-and-suspenders; never patch in production
        return
    import importlib

    patched = []
    for module_name, class_name, subdir in _CLIENTS:
        module = importlib.import_module(module_name)
        klass = getattr(module, class_name)
        if getattr(klass, "_devmock_patched", False):
            continue
        klass._get = _make_get(subdir)
        klass._devmock_patched = True
        # Force base_url truthy so views' `if lg.base_url:` guards pass even
        # when no IXP_LOOKING_GLASS_URL / ALICE_LG_URL is configured.

        def make_init(orig, sub):
            def __init__(self, *args, **kwargs):
                orig(self, *args, **kwargs)
                if not self.base_url:
                    self.base_url = f"devmock://{sub}"
            return __init__

        klass.__init__ = make_init(klass.__init__, subdir)
        patched.append(class_name)

    logger.info("[devmock] fixtures installed for: %s", ", ".join(patched) or "(none)")
