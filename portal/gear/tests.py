"""Tests for peering-gear: host routing, admin gating, slot states, needs, sankey."""

import time
from datetime import date
from unittest import mock

from django.contrib.auth import get_user_model
from django.test import SimpleTestCase, TestCase, override_settings

from gear import analysis

TODAY = date(2026, 11, 5)


def _slot(bay, kind, module=None, accepts=None):
    return {"bay": bay, "kind": kind, "label": "", "position": "", "accepts": accepts or {}, "module": module}


def _mod(model="X", **kw):
    m = {"manufacturer": "Acme", "model": model, "description": "", "profile": None, "attributes": {},
         "serial": "", "status": "active", "mfg_date": None, "power_on_hours": None,
         "endurance_used_pct": None, "donor": None, "donated_on": None}
    m.update(kw)
    return m


def _server():
    slots = [
        _slot("Mainboard", "mainboard", _mod("BOARD", attributes={"max_memory_gb": 128, "dimm_slots": 4})),
        _slot("CPU", "cpu", _mod("Intel Xeon E5-2697 v3")),
        _slot("DIMMA1", "memory", _mod("RAM16", attributes={"size": 16, "class": "DDR4"}), {"class": "DDR4", "ecc": True, "registered": True}),
        _slot("DIMMA2", "memory", None, {"class": "DDR4", "ecc": True, "registered": True}),
        _slot("DIMMB1", "memory", _mod("RAM16", attributes={"size": 16}, donor="Example Donor", donated_on="2026-10-01")),
        _slot("DIMMB2", "memory", None),
        _slot("SATA 3", "disk", _mod("Samsung SSD 870 QVO 4TB", endurance_used_pct=94, power_on_hours=24000, attributes={"type": "SSD"})),
        _slot("SATA 4", "disk", _mod("Samsung SSD 870 QVO 4TB", endurance_used_pct=20, attributes={"type": "SSD"})),
        _slot("PSU1", "psu", _mod("PWS-1")),
        _slot("PSU2", "psu", None),
    ]
    return {"name": "pve-test", "role": "vm-hypervisor", "site": "x", "manufacturer": "Supermicro",
            "model": "SYS-6029U-TR4T", "serial": "", "mfg_date": None, "donor": None, "donated_on": None,
            "netbox_url": "#", "slots": slots}


def _switch():
    slots = [
        _slot("PSU 1", "psu", _mod("PWR-500AC-F")),
        _slot("PSU 2", "psu", _mod("PWR-500AC-F")),
        _slot("Ethernet1", "transceiver", _mod("OLD", mfg_date="2006-01-01"), {"form_factor": "SFP+"}),
        _slot("Ethernet2", "transceiver", None, {"form_factor": "SFP+"}),
        _slot("Ethernet49", "transceiver", _mod("PLANNED", status="planned", donor="Pledger"), {"form_factor": "QSFP28"}),
    ]
    return {"name": "sw-test", "role": "peering_switch", "site": "y", "manufacturer": "Arista",
            "model": "DCS-7280SR-48C6-F", "serial": "", "mfg_date": "2018-10-12", "donor": None,
            "donated_on": None, "netbox_url": "#", "slots": slots}


class AnalysisTests(SimpleTestCase):
    def setUp(self):
        self.fleet = analysis.enrich([_server(), _switch()], TODAY)
        self.srv, self.sw = self.fleet

    def state(self, dev, bay):
        return next(s["state"] for s in dev["slots"] if s["bay"] == bay)

    def test_slot_states(self):
        self.assertEqual(self.state(self.srv, "SATA 3"), "critical")  # 94% endurance
        self.assertEqual(self.state(self.srv, "SATA 4"), "ok")
        self.assertEqual(self.state(self.srv, "DIMMA2"), "empty")
        self.assertEqual(self.state(self.sw, "Ethernet1"), "aging")  # 20 years old
        self.assertEqual(self.state(self.sw, "Ethernet49"), "wished")

    def test_age_from_chassis_or_cpu_generation(self):
        self.assertEqual(self.sw["built_year"], 2018)
        self.assertEqual(self.sw["age_basis"], "built")
        self.assertEqual(self.srv["built_year"], 2014)
        self.assertEqual(self.srv["age_basis"], "cpu generation")

    def test_memory_fill(self):
        self.assertEqual(self.srv["memory"]["installed_gb"], 32)
        self.assertEqual(self.srv["memory"]["max_gb"], 128)
        self.assertEqual(self.srv["memory"]["filled"], 2)

    def test_needs(self):
        ns = analysis.needs(self.fleet, TODAY)
        by = {(n.device, n.category, n.title) for n in ns}
        self.assertIn(("pve-test", "memory", "2 empty DIMM slots"), by)
        self.assertIn(("pve-test", "disk", "1 drive near end of life"), by)
        self.assertIn(("pve-test", "psu", "No redundant power supply"), by)
        self.assertIn(("sw-test", "chassis", "DCS-7280SR-48C6-F from 2018 (8 years)"), by)
        self.assertIn(("sw-test", "transceiver", "1 empty SFP+ cage"), by)
        wish = next(n for n in ns if n.category == "wish")
        self.assertEqual(wish.severity, 3)
        self.assertIn("Pledger", wish.detail)
        mem = next(n for n in ns if n.category == "memory")
        self.assertIn("ECC RDIMM", mem.suggestion)
        self.assertIn("32 GB", mem.suggestion)  # 128 GB / 4 slots
        self.assertEqual(ns[0].severity, 3)  # sorted most urgent first

    def test_donations_and_spares(self):
        rows = analysis.donations(self.fleet)
        self.assertEqual({(r["donor"], r["status"]) for r in rows}, {("Example Donor", "installed"), ("Pledger", "pledged")})
        sp = {r["model"]: r for r in analysis.spares(self.fleet)}
        self.assertEqual(sp["PWR-500AC-F"]["in_service"], 2)
        self.assertNotIn("PLANNED", sp)  # wishes aren't in service

    def test_sankey_layout(self):
        flow = analysis.donations_flow(analysis.donations(self.fleet))
        self.assertEqual(len(flow["links"]), 4)  # 2 donor->device, 2 device->kind
        first = [n for n in flow["nodes"] if n["col"] == 0]
        self.assertTrue(all(n["anchor"] == "end" for n in first))
        self.assertIsNone(analysis.donations_flow([]))


@override_settings(
    GEAR_HOSTS=["gear.test"], ALLOWED_HOSTS=["*"], GEAR_USE_FIXTURES=False,
    STORAGES={
        "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
        "staticfiles": {"BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage"},
    },
)
class RoutingAndAuthTests(TestCase):
    def setUp(self):
        self.fleet_patch = mock.patch("gear.data.get_fleet", return_value=[_server(), _switch()])
        self.fleet_patch.start()
        self.addCleanup(self.fleet_patch.stop)
        self.user = get_user_model().objects.create_user("admin@example.org", "admin@example.org")

    def login(self, admin):
        self.client.force_login(self.user)
        s = self.client.session
        s["oidc_is_ix_admin"] = admin
        # Else mozilla-django-oidc's SessionRefresh bounces us back through SSO.
        s["oidc_id_token_expiration"] = time.time() + 3600
        s.save()

    def test_anonymous_redirects_to_login(self):
        r = self.client.get("/", HTTP_HOST="gear.test")
        self.assertEqual(r.status_code, 302)
        self.assertIn("/login/", r["Location"])

    def test_non_admin_forbidden(self):
        self.login(False)
        r = self.client.get("/", HTTP_HOST="gear.test")
        self.assertEqual(r.status_code, 403)

    def test_admin_pages(self):
        self.login(True)
        for path in ("/", "/needs/", "/donations/", "/device/pve-test/"):
            r = self.client.get(path, HTTP_HOST="gear.test")
            self.assertEqual(r.status_code, 200, path)
        self.assertContains(self.client.get("/device/pve-test/", HTTP_HOST="gear.test"), "A donation could go here")
        self.assertEqual(self.client.get("/device/nope/", HTTP_HOST="gear.test").status_code, 404)

    def test_other_hosts_keep_portal_urls(self):
        self.login(True)
        r = self.client.get("/needs/", HTTP_HOST="portal.test")
        self.assertEqual(r.status_code, 404)  # gear routes don't leak onto the portal

    def test_refresh_rejects_offsite_next(self):
        self.login(True)
        r = self.client.post("/refresh/", {"next": "https://evil.example/"}, HTTP_HOST="gear.test")
        self.assertEqual(r["Location"], "/")
