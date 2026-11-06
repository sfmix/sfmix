"""Tell #pledges about new hardware pledges (Slack incoming webhook).

Fire-and-forget on a daemon thread: a slow or failing Slack never delays or
breaks the pledge form. Off when settings.GEAR_PLEDGE_SLACK_WEBHOOK is empty.
The message carries no email address -- follow-up details stay in the
admin-only pledge table it links to.
"""

from __future__ import annotations

import logging
import threading

import httpx
from django.conf import settings

logger = logging.getLogger(__name__)


def _esc(s: str) -> str:
    # Slack mrkdwn control characters; also defuses <!channel>-style mentions.
    return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def pledge_message(p, base_url: str) -> dict:
    who = _esc(p.name) + (f" ({_esc(p.organization)})" if p.organization else "")
    what = f"{p.quantity}× {_esc(p.item_title or 'something else')}"
    lines = [f":gift: *New hardware pledge:* {what}", f"*From:* {who}",
             "*Member:* yes" if p.is_member else "*Member:* no (counts toward the non-member income limit)"]
    if p.show_as_donor:
        credit = _esc(p.display_name) + (f" — {_esc(p.url)}" if p.url else "")
        lines.append(f"*Donor wall:* yes, as {credit} (after confirmation)")
    else:
        lines.append("*Donor wall:* no")
    if p.details:
        details = _esc(p.details.strip())
        lines.append("> " + (details[:500] + "…" if len(details) > 500 else details).replace("\n", "\n> "))
    lines.append(f"<{base_url}/donations/#pledges|Review and follow up>")
    return {"text": "\n".join(lines), "unfurl_links": False}


def _post(url: str, payload: dict, pk: int) -> None:
    try:
        r = httpx.post(url, json=payload, timeout=10)
        r.raise_for_status()
    except Exception:
        logger.exception("peering-gear: Slack notification for pledge #%d failed", pk)


def notify_new_pledge(p, base_url: str) -> None:
    url = getattr(settings, "GEAR_PLEDGE_SLACK_WEBHOOK", "")
    if not url:
        return
    threading.Thread(target=_post, args=(url, pledge_message(p, base_url), p.pk),
                     name=f"pledge-notify-{p.pk}", daemon=True).start()
