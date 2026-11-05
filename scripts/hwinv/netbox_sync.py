"""Write a collected ``DeviceHardware`` into NetBox as module bays + modules.

Model (see documentation/design_docs/010-peering-gear-hardware-fleet.md):
  slot            -> dcim.modulebay   (cf.slot_kind, cf.slot_accepts, label)
  part            -> dcim.module      (status, serial, cf.mfg_date, cf.hw_last_seen,
                                       cf.power_on_hours, cf.endurance_used_pct)
  part number     -> dcim.moduletype  (manufacturer + model, profile + attributes)
  chassis         -> dcim.device      (serial, cf.mfg_date, cf.hw_last_seen)

Rules:
  * Everything this tool creates carries the ``hwinv`` tag.
  * A ``planned`` module is a donation wish -- never pruned. When real hardware
    shows up in its bay, the wish is replaced by the real module and its
    donor / donated_on fields carry over (the donation is fulfilled).
  * A module whose part is gone is deleted only if it is hwinv-tagged and its
    kind is in the collector's ``authoritative_kinds``; otherwise we warn.
  * Bays are never deleted.
"""

from __future__ import annotations

import logging
import re
from datetime import date
from typing import Any, Dict, List, Optional, Tuple

from .model import KIND_PROFILE, DeviceHardware, Part, Slot

logger = logging.getLogger("hwinv")

TAG = "hwinv"
DONOR_FIELDS = ("donor", "donated_on")
REQUIRED_CUSTOM_FIELDS = (
    "slot_kind", "slot_accepts", "mfg_date", "hw_last_seen",
    "power_on_hours", "endurance_used_pct", "donor", "donated_on",
)


def slugify(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")[:100]


class Stats(dict):
    def bump(self, k: str, n: int = 1) -> None:
        self[k] = self.get(k, 0) + n


class NetBoxHardwareSync:
    def __init__(self, nb: Any, dry_run: bool = True) -> None:
        self.nb = nb
        self.dry_run = dry_run
        self.today = date.today().isoformat()
        self.stats = Stats()
        self._manufacturers: Dict[str, Any] = {}
        self._module_types: Dict[Tuple[int, str], Any] = {}
        self._profiles: Dict[str, Any] = {}
        self._tag_id: Optional[int] = None
        self._new_mfr_ids = -1  # fake ids for dry-run creations

    # ── schema / lookups ──────────────────────────────────────────────

    def preflight(self) -> None:
        """Fail fast if the schema playbook hasn't been applied."""
        have = {cf.name for cf in self.nb.extras.custom_fields.all()}
        missing = [n for n in REQUIRED_CUSTOM_FIELDS if n not in have]
        tag = self.nb.extras.tags.get(slug=TAG)
        self._profiles = {p.name: p for p in self.nb.dcim.module_type_profiles.all()}
        missing_profiles = [p for p in set(KIND_PROFILE.values()) if p not in self._profiles]
        if missing or not tag or missing_profiles:
            msg = (
                "NetBox schema incomplete (custom fields %s, tag %s, profiles %s). Apply "
                "ansible/netbox_schema.playbook.yml first." % (missing, "ok" if tag else "MISSING", missing_profiles)
            )
            if not self.dry_run:
                raise RuntimeError(msg)
            logger.warning("[DRY-RUN] %s Continuing with placeholders.", msg)
            for p in missing_profiles:
                self._profiles[p] = _Fake(id=-1, name=p, schema={})
        self._tag_id = tag.id if tag else -1
        for m in self.nb.dcim.manufacturers.all():
            self._manufacturers[m.name.lower()] = m
            self._manufacturers[m.slug] = m
        for mt in self.nb.dcim.module_types.all():
            self._module_types[(mt.manufacturer.id, mt.model.lower())] = mt
        logger.info(
            "preflight ok: %d manufacturers, %d module types, %d profiles",
            len({m.id for m in self._manufacturers.values()}), len(self._module_types), len(self._profiles),
        )

    def _manufacturer(self, name: str) -> Any:
        key = name.lower()
        m = self._manufacturers.get(key) or self._manufacturers.get(slugify(name))
        if m:
            return m
        self.stats.bump("manufacturers_created")
        if self.dry_run:
            logger.info("[DRY-RUN] Would create manufacturer %s", name)
            m = _Fake(id=self._new_mfr_ids, name=name)
            self._new_mfr_ids -= 1
        else:
            m = self.nb.dcim.manufacturers.create(name=name, slug=slugify(name))
            logger.info("created manufacturer %s", name)
        self._manufacturers[key] = m
        return m

    def _profile_attributes(self, kind: str, attrs: Dict[str, Any]) -> Tuple[Optional[Any], Optional[Dict[str, Any]]]:
        profile = self._profiles.get(KIND_PROFILE.get(kind, ""))
        if not profile:
            return None, None
        schema = dict(profile.schema or {})
        props = schema.get("properties", {})
        clean = {}
        for k, v in attrs.items():
            if v is None or k not in props:
                continue
            spec = props[k]
            if "enum" in spec and v not in spec["enum"]:
                continue
            clean[k] = v
        if any(r not in clean for r in schema.get("required", [])):
            return profile, None  # keep the profile, skip attributes we can't satisfy
        return profile, clean or None

    def _module_type(self, slot: Slot) -> Any:
        part = slot.part
        assert part is not None
        mfr = self._manufacturer(part.manufacturer)
        key = (mfr.id, part.model.lower())
        mt = self._module_types.get(key)
        profile, attrs = self._profile_attributes(slot.kind, part.attributes)
        if mt is not None:
            # Fill in profile/attributes on module types that predate this tool,
            # but never overwrite curated values.
            patch: Dict[str, Any] = {}
            if profile and not getattr(mt, "profile", None):
                patch["profile"] = profile.id
                if attrs:
                    patch["attributes"] = attrs
            if patch and getattr(mt, "id", 0) > 0:
                self.stats.bump("module_types_updated")
                if self.dry_run:
                    logger.info("[DRY-RUN] Would set profile on module type %s %s", part.manufacturer, part.model)
                else:
                    mt.update(patch)
            return mt
        self.stats.bump("module_types_created")
        payload = {
            "manufacturer": mfr.id,
            "model": part.model,
            "part_number": part.model,
            "description": part.description[:200],
            "tags": [self._tag_id],
        }
        if profile:
            payload["profile"] = profile.id
            if attrs:
                payload["attributes"] = attrs
        if self.dry_run or getattr(mfr, "id", 0) < 0:
            logger.info("[DRY-RUN] Would create module type %s %s (%s)", part.manufacturer, part.model, profile and profile.name)
            mt = _Fake(id=-len(self._module_types) - 1, model=part.model, manufacturer=mfr)
        else:
            mt = self.nb.dcim.module_types.create(**payload)
            logger.info("created module type %s %s", part.manufacturer, part.model)
        self._module_types[key] = mt
        return mt

    # ── per-device sync ───────────────────────────────────────────────

    def sync(self, hw: DeviceHardware) -> None:
        dev = self.nb.dcim.devices.get(name=hw.name)
        if dev is None:
            logger.error("%s: not in NetBox, skipping", hw.name)
            return
        self._sync_chassis(dev, hw)
        bays = {b.name: b for b in self.nb.dcim.module_bays.filter(device_id=dev.id)}
        modules = {m.module_bay.id: m for m in self.nb.dcim.modules.filter(device_id=dev.id)}

        bays = self._sync_bays(dev, hw, bays)
        to_create: List[Dict[str, Any]] = []
        for slot in hw.slots:
            bay = bays.get(slot.bay)
            existing = modules.get(bay.id) if bay is not None and bay.id > 0 else None
            payload = self._sync_slot(dev, hw, slot, bay, existing)
            if payload:
                to_create.append(payload)
        if to_create:
            self.stats.bump("modules_created", len(to_create))
            if self.dry_run:
                for p in to_create:
                    logger.info("[DRY-RUN] Would install %s in %s:%s", p["_desc"], hw.name, p["_bay"])
            else:
                for p in to_create:
                    p.pop("_desc"), p.pop("_bay")
                self.nb.dcim.modules.create(to_create)
                logger.info("%s: installed %d modules", hw.name, len(to_create))

    def _sync_chassis(self, dev: Any, hw: DeviceHardware) -> None:
        patch: Dict[str, Any] = {}
        cf = dict(dev.custom_fields or {})
        if hw.serial and (dev.serial or "").strip() != hw.serial:
            if (dev.serial or "").strip():
                logger.warning("%s: NetBox serial %r != hardware serial %r; updating", hw.name, dev.serial, hw.serial)
            patch["serial"] = hw.serial
        cf_patch = {"hw_last_seen": self.today}
        if hw.mfg_date and cf.get("mfg_date") != hw.mfg_date.isoformat():
            cf_patch["mfg_date"] = hw.mfg_date.isoformat()
        if any(cf.get(k) != v for k, v in cf_patch.items()):
            patch["custom_fields"] = cf_patch
        model = hw.facts.get("system_model") or hw.facts.get("model")
        if model and dev.device_type.model.lower() not in model.lower() and model.lower() not in dev.device_type.model.lower():
            logger.warning("%s: NetBox device type %r but hardware reports %r", hw.name, dev.device_type.model, model)
            self.stats.bump("device_type_mismatches")
        if patch:
            self.stats.bump("devices_updated")
            if self.dry_run:
                logger.info("[DRY-RUN] Would update device %s: %s", hw.name, patch)
            else:
                dev.update(patch)

    def _sync_bays(self, dev: Any, hw: DeviceHardware, bays: Dict[str, Any]) -> Dict[str, Any]:
        new: List[Dict[str, Any]] = []
        for slot in hw.slots:
            want_cf = {"slot_kind": slot.kind, "slot_accepts": slot.accepts or None}
            bay = bays.get(slot.bay)
            if bay is None:
                new.append(
                    {
                        "device": dev.id,
                        "name": slot.bay,
                        "label": slot.label[:64],
                        "position": slot.position or "",
                        "custom_fields": want_cf,
                        "tags": [self._tag_id],
                    }
                )
                continue
            cf = dict(bay.custom_fields or {})
            patch: Dict[str, Any] = {}
            if any(cf.get(k) != v for k, v in want_cf.items()):
                patch["custom_fields"] = want_cf
            if slot.label and bay.label != slot.label[:64]:
                patch["label"] = slot.label[:64]
            if patch:
                self.stats.bump("bays_updated")
                if self.dry_run:
                    logger.debug("[DRY-RUN] Would update bay %s:%s %s", hw.name, slot.bay, patch)
                else:
                    bay.update(patch)
        if new:
            self.stats.bump("bays_created", len(new))
            if self.dry_run:
                logger.info("[DRY-RUN] Would create %d bays on %s (%s ...)", len(new), hw.name, ", ".join(b["name"] for b in new[:6]))
                for i, b in enumerate(new):
                    bays[b["name"]] = _Fake(id=-(i + 1), name=b["name"])
            else:
                for b in self.nb.dcim.module_bays.create(new):
                    bays[b.name] = b
                logger.info("%s: created %d bays", hw.name, len(new))
        return bays

    def _module_cf(self, part: Part) -> Dict[str, Any]:
        # No per-module last-seen stamp: it would PATCH every module on every
        # run and flood the changelog. The device's hw_last_seen covers it.
        return {
            "mfg_date": part.mfg_date.isoformat() if part.mfg_date else None,
            "power_on_hours": part.power_on_hours,
            "endurance_used_pct": part.endurance_used_pct,
        }

    def _sync_slot(self, dev: Any, hw: DeviceHardware, slot: Slot, bay: Any, existing: Any) -> Optional[Dict[str, Any]]:
        """Reconcile one bay. Returns a module-create payload, or None."""
        part = slot.part
        authoritative = slot.kind in hw.authoritative_kinds
        is_ours = existing is not None and any(t.slug == TAG for t in (existing.tags or []))
        planned = existing is not None and existing.status.value == "planned"

        if part is None:
            if existing is None or planned:
                return None
            if is_ours and authoritative:
                self.stats.bump("modules_removed")
                if self.dry_run:
                    logger.info("[DRY-RUN] Would remove %s from %s:%s (no longer present)", existing.module_type.model, hw.name, slot.bay)
                else:
                    existing.delete()
                    logger.info("%s:%s: removed %s (no longer present)", hw.name, slot.bay, existing.module_type.model)
            else:
                logger.warning("%s:%s: NetBox has %s but hardware reports empty", hw.name, slot.bay, existing.module_type.model)
            return None

        mt = self._module_type(slot)
        carry: Dict[str, Any] = {}
        if existing is not None:
            same_type = existing.module_type.id == mt.id
            same_serial = (existing.serial or None) == (part.serial or None)
            if same_type and same_serial and not planned:
                self._update_module(hw, slot, existing, part)
                return None
            if planned:
                carry = {k: v for k, v in dict(existing.custom_fields or {}).items() if k in DONOR_FIELDS and v}
                self.stats.bump("wishes_fulfilled")
                verb = "fulfil wish"
            elif not is_ours:
                logger.warning(
                    "%s:%s: hand-entered %s differs from hardware %s %s; leaving it",
                    hw.name, slot.bay, existing.module_type.model, part.model, part.serial,
                )
                return None
            else:
                carry = {k: v for k, v in dict(existing.custom_fields or {}).items() if k in DONOR_FIELDS and v and same_serial}
                self.stats.bump("modules_replaced")
                verb = "replace"
            if self.dry_run:
                logger.info("[DRY-RUN] Would %s %s:%s %s -> %s", verb, hw.name, slot.bay, existing.module_type.model, part.model)
            else:
                existing.delete()
        cf = {k: v for k, v in self._module_cf(part).items() if v is not None}
        cf.update(carry)
        return {
            "device": dev.id,
            "module_bay": bay.id,
            "module_type": mt.id,
            "status": part.status,
            "serial": part.serial or "",
            "custom_fields": cf,
            "tags": [self._tag_id],
            "replicate_components": False,
            "adopt_components": False,
            "_desc": f"{part.manufacturer} {part.model} {part.serial or ''}".strip(),
            "_bay": slot.bay,
        }

    def _update_module(self, hw: DeviceHardware, slot: Slot, mod: Any, part: Part) -> None:
        cf = dict(mod.custom_fields or {})
        want = {k: v for k, v in self._module_cf(part).items() if v is not None}
        patch: Dict[str, Any] = {}
        if any(cf.get(k) != v for k, v in want.items()):
            patch["custom_fields"] = want
        if mod.status.value != part.status:
            patch["status"] = part.status
        if TAG not in {t.slug for t in (mod.tags or [])}:
            patch["tags"] = [t.id for t in (mod.tags or [])] + [self._tag_id]
        if patch:
            self.stats.bump("modules_updated")
            if self.dry_run:
                logger.debug("[DRY-RUN] Would update module %s:%s %s", hw.name, slot.bay, patch)
            else:
                mod.update(patch)


class _Fake:
    """Placeholder for objects that would be created (dry-run)."""

    def __init__(self, **kw: Any) -> None:
        self.__dict__.update(kw)
