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


class IncomingHardwareTests(SimpleTestCase):
    """Hand-recorded servers on hand but not installed (status=inventory)."""

    def _dl360(self):
        hot = {"bus": "SAS/SATA", "form_factor": "2.5in SFF", "hot_swap": True}
        slots = [
            _slot("Mainboard", "mainboard", _mod("board", attributes={"max_memory_gb": 768, "dimm_slots": 24})),
            _slot("PROC 1 DIMM 1", "memory", _mod("RAM32", attributes={"size": 32, "class": "DDR4"}),
                  {"class": "DDR4", "ecc": True, "registered": True}),
            _slot("PROC 1 DIMM 2", "memory", None, {"class": "DDR4", "ecc": True, "registered": True}),
            _slot("Drive Bay 1", "disk", _mod("128GB SATA SSD", flagged_worn=True, attributes={"type": "SSD"}), hot),
            _slot("Drive Bay 2", "disk", _mod("128GB SATA SSD", status="failed", flagged_worn=True, attributes={"type": "SSD"}), hot),
            _slot("Drive Bay 3", "disk", None, hot),
        ]
        return {"name": "incoming-1", "role": "vm-hypervisor", "status": "inventory", "site": "unassigned",
                "manufacturer": "HPE", "model": "ProLiant DL360 Gen9", "serial": "", "mfg_date": None,
                "donor": None, "donated_on": None, "netbox_url": "#", "slots": slots}

    def test_incoming_grouping_states_and_needs(self):
        fleet = analysis.enrich([self._dl360(), _switch()], TODAY)
        groups = analysis.by_role(fleet)
        self.assertEqual(groups[0]["role"], "incoming")
        self.assertEqual([d["name"] for d in groups[0]["devices"]], ["incoming-1"])
        self.assertNotIn("incoming-1", [d["name"] for g in groups[1:] for d in g["devices"]])
        dev = fleet[0]
        states = {s["bay"]: s["state"] for s in dev["slots"]}
        self.assertEqual(states["Drive Bay 1"], "worn")  # manual hw-worn tag
        self.assertEqual(states["Drive Bay 2"], "critical")  # failed beats worn
        self.assertEqual((dev["built_year"], dev["age_basis"]), (2014, "platform generation"))
        titles = {(n.category, n.title) for n in analysis.needs(fleet, TODAY) if n.device == "incoming-1"}
        self.assertIn(("disk", "1 drive near end of life"), titles)
        self.assertIn(("disk", "1 drive worn / aging"), titles)
        self.assertIn(("disk", "1 empty drive bay"), titles)  # hot-swap bay without SES
        self.assertIn(("memory", "1 empty DIMM slot"), titles)

    def test_chassis_on_hand_counts_as_spare(self):
        spare = {**_switch(), "name": "old-sw", "status": "inventory", "slots": []}
        fleet = analysis.enrich([_switch(), spare, self._dl360()], TODAY)
        rows = {(r["kind"], r["model"]): r for r in analysis.spares(fleet)}
        sw = rows[("Chassis", "DCS-7280SR-48C6-F")]
        self.assertEqual((sw["in_service"], sw["spares"]), (1, 1))
        self.assertNotIn(("Chassis", "ProLiant DL360 Gen9"), rows)  # not in service -> no spare row
        self.assertEqual(analysis.stats(fleet, [])["spares"], 1)


class NetBoxMappingTests(SimpleTestCase):
    """data._fetch_from_netbox against NetBox-shaped API payloads."""

    API = {
        "dcim/devices": [{
            "id": 7, "name": "sw-test", "role": {"slug": "peering_switch"}, "site": {"name": "SFO01"},
            "device_type": {"model": "DCS-7280SR-48C6-F", "manufacturer": {"name": "Arista"}},
            "serial": "ABC", "custom_fields": {"mfg_date": "2018-10-12", "hw_last_seen": "2026-11-05", "donor": None, "donated_on": None},
        }],
        "dcim/module-bays": [
            {"id": 1, "device": {"id": 7}, "name": "PSU 1", "label": "", "position": "1",
             "custom_fields": {"slot_kind": {"value": "psu", "label": "Power supply"}, "slot_accepts": None}},
            {"id": 2, "device": {"id": 7}, "name": "Ethernet2", "label": "SFP+ cage", "position": "2",
             "custom_fields": {"slot_kind": {"value": "transceiver", "label": "Transceiver"}, "slot_accepts": {"form_factor": "SFP+"}}},
            {"id": 3, "device": {"id": 7}, "name": "Cassette A", "label": "", "position": "",
             "custom_fields": {"slot_kind": None, "slot_accepts": None}},
        ],
        "dcim/modules": [{
            "id": 9, "module_bay": {"id": 1}, "module_type": {"id": 5}, "serial": "P1",
            "status": {"value": "active", "label": "Active"},
            "custom_fields": {"mfg_date": None, "power_on_hours": None, "endurance_used_pct": None,
                              "donor": "Example Donor", "donated_on": "2026-01-02"},
        }],
        "dcim/module-types": [{
            "id": 5, "model": "PWR-500AC-F", "description": "500W", "manufacturer": {"name": "Arista"},
            "profile": {"name": "Power supply"}, "attributes": {"wattage": 500},
        }],
    }

    @override_settings(IXP_NETBOX_URL="https://nb.test", GEAR_DEVICE_ROLES=["peering_switch"])
    def test_maps_netbox_payloads(self):
        from gear import data

        with mock.patch.object(data, "_get_all", side_effect=lambda path, params: self.API[path]):
            fleet = data._fetch_from_netbox()
        dev = fleet[0]
        self.assertEqual([s["bay"] for s in dev["slots"]], ["PSU 1", "Ethernet2"])  # unmodeled bay skipped
        psu, cage = dev["slots"]
        self.assertEqual(psu["kind"], "psu")  # select CF unwrapped to its value
        self.assertEqual(psu["module"]["donor"], "Example Donor")
        self.assertEqual(psu["module"]["attributes"]["wattage"], 500)
        self.assertIsNone(cage["module"])
        self.assertEqual(cage["accepts"], {"form_factor": "SFP+"})
        # And the analysis accepts it end to end.
        analysis.enrich(fleet, TODAY)
        self.assertEqual(dev["slots"][1]["state"], "empty")


@override_settings(
    GEAR_USE_FIXTURES=False,
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache", "LOCATION": "gear-snap"}},
)
class SnapshotTests(SimpleTestCase):
    def setUp(self):
        from django.core.cache import cache

        cache.clear()

    def test_stale_snapshot_served_without_fetch(self):
        from django.core.cache import cache
        from gear import data

        cache.set(data.CACHE_KEY, {"fleet": ["old"], "fetched_at": time.time() - 10 * data.REFRESH_INTERVAL}, None)
        with mock.patch.object(data, "_fetch_from_netbox") as fetch:
            self.assertEqual(data.get_fleet(), ["old"])
            fetch.assert_not_called()
        self.assertTrue(data._is_stale())  # ...and the warmer will replace it

    def test_cold_start_and_refresh_fetch(self):
        from gear import data

        with mock.patch.object(data, "_fetch_from_netbox", return_value=["new"]) as fetch:
            self.assertEqual(data.get_fleet(), ["new"])  # no snapshot yet: fetch once
            self.assertEqual(data.get_fleet(), ["new"])
            self.assertEqual(fetch.call_count, 1)
            data.get_snapshot(refresh=True)
            self.assertEqual(fetch.call_count, 2)
        self.assertFalse(data._is_stale())


class WishlistTests(SimpleTestCase):
    def setUp(self):
        self.fleet = analysis.enrich([_server(), _switch()], TODAY)

    def test_groups_by_what_to_buy(self):
        wl = {w["slug"]: w for w in analysis.wishlist(self.fleet, {"ddr4-rdimm": 5})}
        rdimm = wl["ddr4-rdimm"]
        self.assertEqual(rdimm["units"], 1)  # DIMMA2; DIMMB2 has no known spec
        self.assertEqual(rdimm["pledged"], 1)  # capped at what's wanted
        self.assertEqual(rdimm["remaining"], 0)
        self.assertIn("takes up to 32 GB per slot", rdimm["devices"][0]["current"])
        ssd = wl["ssd-2.5"]
        self.assertEqual((ssd["units"], ssd["severity"]), (1, 3))  # the 94% QVO
        self.assertIn("94% endurance", ssd["devices"][0]["current"])
        self.assertEqual(wl["psu-pws-1"]["severity"], 3)  # one PSU of two
        self.assertNotIn("psu-pwr-500ac-f", wl)  # switch PSUs are redundant

    def test_empty_hot_swap_bays_and_form_factor(self):
        dev = _server()
        dev["slots"] += [
            _slot("Bay 1", "disk", None, {"bus": "SAS/SATA", "form_factor": "2.5in SFF", "hot_swap": True}),
            _slot("SATA 5", "disk", None, {"bus": "ATA"}),  # bare port: not wanted
            _slot("Bay 2", "disk", _mod("ST4000DM000", description="4TB HD 3.5 inches", power_on_hours=80000)),
        ]
        wl = {w["slug"]: w for w in analysis.wishlist(analysis.enrich([dev], TODAY))}
        self.assertEqual(wl["ssd-2.5"]["units"], 2)  # worn QVO + empty SFF bay
        self.assertEqual(wl["drive-3.5"]["units"], 1)

    def test_donor_wall(self):
        dev = _server()
        dev["donor"] = "jof"
        rows = analysis.donations(analysis.enrich([dev], TODAY))
        wall = analysis.donor_wall(rows, [{"name": "Acme", "url": "https://acme.test/", "item": "DIMMs"}])
        self.assertEqual([w["name"] for w in wall], ["Example Donor", "jof", "Acme"])
        self.assertEqual({w["name"]: w["given"] for w in wall[:2]}, {"jof": ["1 chassis"], "Example Donor": ["1 DIMM"]})
        self.assertEqual(wall[2]["pledged"], ["DIMMs"])


@override_settings(
    GEAR_HOSTS=["gear.test"], ALLOWED_HOSTS=["*"], GEAR_USE_FIXTURES=False,
    STORAGES={
        "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
        "staticfiles": {"BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage"},
    },
)
class RoutingAndAuthTests(TestCase):
    def setUp(self):
        self.fleet_patch = mock.patch(
            "gear.data.get_snapshot",
            side_effect=lambda refresh=False: {"fleet": [_server(), _switch()], "fetched_at": time.time() - 300},
        )
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
        for path in ("/", "/needs/", "/donations/", "/device/pve-test/", "/pledge/"):
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

    def test_pledge_flow(self):
        from gear.models import Pledge

        self.login(True)
        r = self.client.get("/pledge/?item=ddr4-rdimm", HTTP_HOST="gear.test")
        self.assertContains(r, 'value="ddr4-rdimm" selected')
        form = {"item_slug": "ddr4-rdimm", "quantity": 4, "name": "Pat", "organization": "Acme",
                "email": "pat@acme.test", "show_as_donor": "on", "url": "https://acme.test/"}
        r = self.client.post("/pledge/", {**form, "website": "spam"}, HTTP_HOST="gear.test")
        self.assertEqual(r.status_code, 200)  # honeypot tripped
        self.assertFalse(Pledge.objects.exists())
        r = self.client.post("/pledge/", form, HTTP_HOST="gear.test")
        p = Pledge.objects.get()
        self.assertRedirects(r, f"/pledge/{p.pk}/thanks/", fetch_redirect_response=False)
        self.assertEqual((p.item_title, p.display_name, p.status), ("DDR4 ECC registered DIMMs (RDIMM)", "Acme", "new"))
        self.assertContains(self.client.get("/needs/", HTTP_HOST="gear.test"), "1 pledged")
        # Not on the wall until an admin confirms it.
        self.assertNotContains(self.client.get("/donations/", HTTP_HOST="gear.test"), 'rel="noopener">Acme')
        self.client.post(f"/pledges/{p.pk}/status/", {"status": "confirmed"}, HTTP_HOST="gear.test")
        self.assertContains(self.client.get("/donations/", HTTP_HOST="gear.test"), 'rel="noopener">Acme')

    def test_pledge_other_needs_details(self):
        self.login(True)
        r = self.client.post("/pledge/", {"item_slug": "", "quantity": 1, "name": "Pat", "email": "p@x.test"},
                             HTTP_HOST="gear.test")
        self.assertContains(r, "Tell us what you")
