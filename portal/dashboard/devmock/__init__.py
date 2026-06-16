"""Local-dev mock data layer for the SFMIX portal.

When ``settings.LG_USE_FIXTURES`` is on (which is itself DEBUG-gated), this
package monkeypatches the ``_get`` method of the upstream API clients so every
page renders from on-disk JSON fixtures instead of hitting the real Looking
Glass / Alice services. See ``loader.install()`` and ``fixtures/README.md``.

Fixtures contain **synthetic placeholder data only** — never real participants.
"""

from .loader import install

__all__ = ["install"]
