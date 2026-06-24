"""Unit tests for route-server parity computation."""

from django.test import SimpleTestCase

from dashboard.views import (
    _build_physical_port,
    _compute_rs_parity,
    _parity_applicable,
    _real_routeservers,
    _rs_session_sort_key,
)

# Two configured route servers, mirroring production (BIRD + OpenBGPD).
ROUTESERVERS = [
    {"id": "rs1", "name": "RS1 (BIRD)"},
    {"id": "rs2", "name": "RS2 (OpenBGPD)"},
]


def _sess(rs_id, addr, state="established", received=100):
    return {
        "rs_id": rs_id,
        "rs_name": rs_id,
        "address": addr,
        "state": state,
        "routes_received": received,
    }


def _both_rs(v4_r1=100, v4_r2=100, v6_r1=50, v6_r2=50,
             v4_s1="established", v4_s2="established",
             v6_s1="established", v6_s2="established"):
    return [
        _sess("rs1", "192.0.2.10", v4_s1, v4_r1),
        _sess("rs1", "2001:db8::10", v6_s1, v6_r1),
        _sess("rs2", "192.0.2.10", v4_s2, v4_r2),
        _sess("rs2", "2001:db8::10", v6_s2, v6_r2),
    ]


class ComputeRsParityTests(SimpleTestCase):
    def test_no_routeservers_returns_none(self):
        self.assertIsNone(_compute_rs_parity(_both_rs(), []))

    def test_ok_when_established_and_counts_match(self):
        p = _compute_rs_parity(_both_rs(), ROUTESERVERS)
        self.assertEqual(p["status"], "ok")
        self.assertEqual(p["severity"], "ok")
        self.assertEqual(p["issues"], [])

    def test_small_delta_within_tolerance_is_ok(self):
        # 118 vs 117 — the fixture case; delta 1 ≤ 2 → OK.
        p = _compute_rs_parity(_both_rs(v4_r1=118, v4_r2=117), ROUTESERVERS)
        self.assertEqual(p["status"], "ok")

    def test_not_peered_when_no_sessions(self):
        p = _compute_rs_parity([], ROUTESERVERS)
        self.assertEqual(p["status"], "not_peered")
        self.assertEqual(p["severity"], "crit")
        self.assertEqual(p["sort_rank"], 1)

    def test_redundancy_broken_when_idle_on_one_rs(self):
        p = _compute_rs_parity(_both_rs(v4_s2="idle"), ROUTESERVERS)
        self.assertEqual(p["status"], "redundancy_broken")
        self.assertEqual(p["severity"], "crit")
        self.assertEqual(p["sort_rank"], 0)
        self.assertTrue(p["issues"])

    def test_redundancy_broken_when_single_homed(self):
        # Present + established on rs1 only; rs2 absent entirely.
        sessions = [
            _sess("rs1", "192.0.2.10"),
            _sess("rs1", "2001:db8::10"),
        ]
        p = _compute_rs_parity(sessions, ROUTESERVERS)
        self.assertEqual(p["status"], "redundancy_broken")
        self.assertEqual(p["sort_rank"], 0)

    def test_prefix_mismatch_over_threshold(self):
        # 338 vs 200 → delta 138, >2 and >10% → mismatch.
        p = _compute_rs_parity(_both_rs(v4_r1=338, v4_r2=200), ROUTESERVERS)
        self.assertEqual(p["status"], "prefix_mismatch")
        self.assertEqual(p["severity"], "warn")
        self.assertEqual(p["sort_rank"], 2)

    def test_prefix_delta_under_pct_is_ok(self):
        # 1000 vs 996 → delta 4 (>2) but <10% → OK.
        p = _compute_rs_parity(_both_rs(v4_r1=1000, v4_r2=996), ROUTESERVERS)
        self.assertEqual(p["status"], "ok")

    def test_parity_uses_received_not_accepted(self):
        # OpenBGPD (rs2) reports no accepted count, only received. Parity must
        # compare received prefixes so the missing accepted field never falsely
        # flags a mismatch. Equal received counts → OK despite rs2 lacking
        # routes_accepted entirely.
        sessions = _both_rs()
        for s in sessions:
            if s["rs_id"] == "rs2":
                s.pop("routes_accepted", None)  # mirror OpenBGPD via Alice
                s["routes_accepted"] = 0
        p = _compute_rs_parity(sessions, ROUTESERVERS)
        self.assertEqual(p["status"], "ok")
        # The displayed per-RS cell carries the received count, not accepted.
        rs2 = next(r for r in p["rs"] if r["rs_id"] == "rs2")
        self.assertEqual(rs2["afs"][0]["received"], 100)

    def test_v4_only_participant_not_faulted_for_missing_v6(self):
        # Established v4 on both RS, no v6 anywhere → symmetric absence is OK.
        sessions = [
            _sess("rs1", "192.0.2.10"),
            _sess("rs2", "192.0.2.10"),
        ]
        p = _compute_rs_parity(sessions, ROUTESERVERS)
        self.assertEqual(p["status"], "ok")
        self.assertEqual(p["afs"], ["v4"])

    def test_v6_idle_on_both_rs_is_ok(self):
        # Participant has v6 sessions configured on both route servers but
        # never brings them up (idle on both). v4 is established on both. The
        # v6 down state is symmetric → not a parity defect → OK.
        p = _compute_rs_parity(
            _both_rs(v6_s1="idle", v6_s2="idle"), ROUTESERVERS)
        self.assertEqual(p["status"], "ok")
        self.assertEqual(p["issues"], [])

    def test_v6_up_on_one_rs_only_is_redundancy_broken(self):
        # v6 established on rs1 but idle on rs2 → genuine asymmetry → flagged.
        p = _compute_rs_parity(_both_rs(v6_s2="idle"), ROUTESERVERS)
        self.assertEqual(p["status"], "redundancy_broken")
        self.assertEqual(p["sort_rank"], 0)
        self.assertTrue(p["issues"])

    def test_all_sessions_down_on_both_rs_is_ok(self):
        # Configured but down on every route server across all address families
        # → symmetric total outage, no asymmetry → OK on the parity page.
        p = _compute_rs_parity(
            _both_rs(v4_s1="idle", v4_s2="idle", v6_s1="idle", v6_s2="idle"),
            ROUTESERVERS,
        )
        self.assertEqual(p["status"], "ok")
        self.assertEqual(p["issues"], [])

    def test_looking_glass_session_does_not_affect_parity(self):
        # The session list passed to parity may contain looking-glass / quarantine
        # collector sessions (they belong in the participant listing). Those are
        # not real route servers, so they must not influence the parity verdict,
        # the compared address families, or the per-RS summary.
        sessions = _both_rs() + [
            _sess("looking_glass", "192.0.2.10"),
            _sess("looking_glass", "2001:db8::10"),
        ]
        p = _compute_rs_parity(sessions, ROUTESERVERS)
        self.assertEqual(p["status"], "ok")
        self.assertEqual(p["issues"], [])
        self.assertEqual({r["rs_id"] for r in p["rs"]}, {"rs1", "rs2"})

    def test_looking_glass_only_af_is_not_compared(self):
        # A participant peered v4 on both real RS, but whose only v6 session is on
        # the looking glass, must not be faulted for "missing" v6 on the real RS:
        # the LG-only family is invisible to parity.
        sessions = [
            _sess("rs1", "192.0.2.10"),
            _sess("rs2", "192.0.2.10"),
            _sess("looking_glass", "2001:db8::10"),
        ]
        p = _compute_rs_parity(sessions, ROUTESERVERS)
        self.assertEqual(p["status"], "ok")
        self.assertEqual(p["afs"], ["v4"])


class PhysicalPortLldpTests(SimpleTestCase):
    """The LLDP neighbor pill must read the field names the looking-glass
    actually serializes. The lg-types LldpNeighbor struct emits
    local_interface / neighbor_device / neighbor_port / ttl — there is no
    system_name, neighbor_interface, or chassis_id. Reading the wrong names
    silently dropped every neighbor to an empty "—" in the participant view.
    """

    DEVICE = "switch03.sjc01.sfmix.org"
    IFACE = "Ethernet22/1"

    def _lldp_by_key(self):
        # Shape exactly as lg_client.get_lldp_neighbors() returns it: the
        # JSON serialization of lg-types::structured::LldpNeighbor.
        entry = {
            "local_interface": self.IFACE,
            "neighbor_device": "unwired-broadband-rtr01",
            "neighbor_port": "xe-0/0/3",
            "ttl": "120",
        }
        return {(self.DEVICE, self.IFACE): entry}

    def _iface_by_key(self):
        return {(self.DEVICE, self.IFACE): {"link_status": "up", "speed": 10000}}

    def test_lldp_neighbor_populates_display_fields(self):
        phy = _build_physical_port(
            self.DEVICE, self.IFACE, self._iface_by_key(), {},
            self._lldp_by_key(), can_see_admin=False,
        )
        self.assertIsNotNone(phy["lldp"])
        self.assertEqual(phy["lldp"]["sys_name"], "unwired-broadband-rtr01")
        self.assertEqual(phy["lldp"]["port_id"], "xe-0/0/3")

    def test_no_lldp_entry_yields_none(self):
        phy = _build_physical_port(
            self.DEVICE, self.IFACE, self._iface_by_key(), {}, {},
            can_see_admin=False,
        )
        self.assertIsNone(phy["lldp"])


class RealRouteserversTests(SimpleTestCase):
    def test_drops_looking_glass_and_quarantine_sources(self):
        # Mirrors the production Alice routeservers list.
        rs = [
            {"id": "rs-linux", "name": "BIRD/Linux Route Server"},
            {"id": "rs-openbsd", "name": "OpenBGPD/OpenBSD Route Server"},
            {"id": "looking_glass", "name": "Looking Glass Service"},
            {"id": "quarantine_looking_glass", "name": "Quarantine VLAN Looking Glass"},
        ]
        kept = [r["id"] for r in _real_routeservers(rs)]
        self.assertEqual(kept, ["rs-linux", "rs-openbsd"])

    def test_keeps_dev_fixture_route_servers(self):
        rs = [{"id": "rs1", "name": "RS1 (BIRD)"}, {"id": "rs2", "name": "RS2 (OpenBGPD)"}]
        self.assertEqual(len(_real_routeservers(rs)), 2)


class ParityApplicableTests(SimpleTestCase):
    def test_routeserver_type_excluded(self):
        self.assertFalse(_parity_applicable({
            "participant_type": "routeserver",
            "ip_addresses": [{"status": "active"}],
        }))

    def test_active_peer_included(self):
        self.assertTrue(_parity_applicable({
            "participant_type": "peer",
            "ip_addresses": [{"status": "active"}],
        }))

    def test_no_active_ip_excluded(self):
        self.assertFalse(_parity_applicable({
            "participant_type": "peer",
            "ip_addresses": [{"status": "reserved"}],
        }))

    def test_never_via_route_servers_excluded(self):
        participant = {
            "asn": 64498,
            "participant_type": "peer",
            "ip_addresses": [{"status": "active"}],
        }
        pdb = {"64498": {"info_never_via_route_servers": True}}
        self.assertFalse(_parity_applicable(participant, pdb))
        # Without the PeeringDB flag, the same participant is applicable.
        self.assertTrue(_parity_applicable(participant))
        self.assertTrue(_parity_applicable(participant, {"64498": {}}))


class RsSessionSortKeyTests(SimpleTestCase):
    """The route-server session list must render in a stable, human order."""

    def _entry(self, name, address):
        # Mirrors the display dict built in _build_logical_ports.
        return {"name": name, "address": address}

    def test_orders_by_name_then_v4_before_v6_then_numeric_ip(self):
        # Deliberately scrambled input, as Alice-LG may return it.
        entries = [
            self._entry("RS2 (OpenBGPD)", "2001:db8::10"),
            self._entry("RS1 (BIRD)", "2001:db8::10"),
            self._entry("RS2 (OpenBGPD)", "192.0.2.10"),
            self._entry("RS1 (BIRD)", "192.0.2.10"),
        ]
        ordered = sorted(entries, key=_rs_session_sort_key)
        self.assertEqual(
            [(e["name"], e["address"]) for e in ordered],
            [
                ("RS1 (BIRD)", "192.0.2.10"),
                ("RS1 (BIRD)", "2001:db8::10"),
                ("RS2 (OpenBGPD)", "192.0.2.10"),
                ("RS2 (OpenBGPD)", "2001:db8::10"),
            ],
        )

    def test_ipv4_sorts_numerically_not_lexically(self):
        entries = [
            self._entry("RS1", "192.0.2.100"),
            self._entry("RS1", "192.0.2.9"),
            self._entry("RS1", "192.0.2.20"),
        ]
        ordered = sorted(entries, key=_rs_session_sort_key)
        self.assertEqual(
            [e["address"] for e in ordered],
            ["192.0.2.9", "192.0.2.20", "192.0.2.100"],
        )

    def test_unparseable_address_sorts_last_without_error(self):
        entries = [
            self._entry("RS1", ""),
            self._entry("RS1", "192.0.2.10"),
            self._entry("RS1", "2001:db8::10"),
        ]
        ordered = sorted(entries, key=_rs_session_sort_key)
        self.assertEqual(
            [e["address"] for e in ordered],
            ["192.0.2.10", "2001:db8::10", ""],
        )

    def test_sort_is_idempotent_and_deterministic(self):
        entries = [
            self._entry("RS2", "192.0.2.10"),
            self._entry("RS1", "2001:db8::10"),
            self._entry("RS1", "192.0.2.10"),
        ]
        once = sorted(entries, key=_rs_session_sort_key)
        twice = sorted(reversed(once), key=_rs_session_sort_key)
        self.assertEqual(once, twice)


class LldpNeighborsViewTtlTests(SimpleTestCase):
    """The LG serializes LldpNeighbor.ttl as a *string* (empty when the device
    omits it), so the view must coerce before comparing. Comparing the raw
    string against an int raised "'<' not supported between instances of 'str'
    and 'int'", which blanked the whole table behind the lg_error banner.
    """

    def _run_view(self, lldp_entries):
        from unittest.mock import MagicMock, patch

        from django.test import RequestFactory

        from dashboard import views

        lg = MagicMock()
        lg.base_url = "https://lg.example"
        lg.get_lldp_neighbors.return_value = [
            {"device": "switch01", "success": True, "data": lldp_entries},
        ]
        lg.get_participant_ports.return_value = []
        lg.get_interfaces_status.return_value = []

        captured = {}

        def fake_render(request, template, context):
            captured.update(context)
            from django.http import HttpResponse
            return HttpResponse("ok")

        request = RequestFactory().get("/admin/lldp/")
        request.session = {}
        request.user = MagicMock(is_authenticated=True)
        with patch.object(views, "LookingGlassClient", return_value=lg), \
                patch.object(views, "_is_ix_admin", return_value=True), \
                patch.object(views, "render", side_effect=fake_render):
            views.lldp_neighbors(request)
        return captured

    def test_string_ttl_does_not_raise_and_is_coerced(self):
        ctx = self._run_view([
            {"local_interface": "Ethernet1", "ttl": "120"},
            {"local_interface": "Ethernet2", "ttl": "15"},
        ])
        self.assertIsNone(ctx["lg_error"])
        by_if = {e["local_interface"]: e for e in ctx["entries"]}
        self.assertEqual(by_if["Ethernet1"]["ttl"], 120)
        self.assertFalse(by_if["Ethernet1"]["ttl_expiring"])
        self.assertEqual(by_if["Ethernet2"]["ttl"], 15)
        self.assertTrue(by_if["Ethernet2"]["ttl_expiring"])

    def test_empty_or_missing_ttl_becomes_none(self):
        ctx = self._run_view([
            {"local_interface": "Ethernet3", "ttl": ""},
            {"local_interface": "Ethernet4"},
        ])
        self.assertIsNone(ctx["lg_error"])
        for e in ctx["entries"]:
            self.assertIsNone(e["ttl"])
            self.assertFalse(e["ttl_expiring"])


# ── ND anomaly events page (Phase 4) ────────────────────────────────

from types import SimpleNamespace
from unittest import mock

from django.test import RequestFactory, override_settings

from dashboard import views

# Render tests don't run collectstatic, so swap the manifest static storage for
# the plain one (otherwise {% static %} in base.html raises on a missing manifest).
_PLAIN_STATIC = override_settings(
    STORAGES={
        "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
        "staticfiles": {"BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage"},
    }
)

_NDEV = {
    "events": [
        {
            "id": "11111111-1111-4111-8111-111111111111",
            "kind": "new_mac_on_ip", "ip": "2001:db8:0:1::10", "family": "IPv6",
            "asn": 64496, "tenant": "Example Networks",
            "old_macs": ["0200.5e10.0a01"], "new_mac": "0200.5e99.dead", "claimed_ips": [],
            "opened_at": "2026-06-18T00:00:30+00:00", "last_seen": "2026-06-18T00:03:00+00:00",
            "flap_count": 3, "evidence_id": "11111111-1111-4111-8111-111111111111", "closed": False,
        },
        {
            "id": "22222222-2222-4222-8222-222222222222",
            "kind": "mac_claims_many_ips", "ip": "", "family": "",
            "asn": None, "tenant": None, "old_macs": [], "new_mac": "0200.5eaa.bbbb",
            "claimed_ips": ["198.51.100.5", "198.51.100.6"],
            "opened_at": "2026-06-17T21:10:00+00:00", "last_seen": "2026-06-17T21:18:00+00:00",
            "flap_count": 2, "evidence_id": None, "closed": True,
        },
    ]
}


def _admin_request(path="/admin/nd-events/", admin=True):
    req = RequestFactory().get(path)
    req.user = SimpleNamespace(is_authenticated=True)
    req.session = {"oidc_is_ix_admin": admin, "oidc_id_token": "tok"}
    return req


@_PLAIN_STATIC
class NdEventsViewTests(SimpleTestCase):
    @mock.patch("dashboard.views.LookingGlassClient")
    def test_renders_both_event_kinds(self, MockLG):
        inst = MockLG.return_value
        inst.base_url = "http://lg"
        inst.get_nd_events.return_value = _NDEV
        resp = views.nd_events(_admin_request())
        self.assertEqual(resp.status_code, 200)
        html = resp.content.decode()
        self.assertIn("MAC sweep", html)
        self.assertIn("new MAC", html)
        self.assertIn("2001:db8:0:1::10", html)      # per-IP subject
        self.assertIn("0200.5eaa.bbbb", html)         # sweep offending MAC
        self.assertIn("/admin/nd-events/11111111-1111-4111-8111-111111111111/pcap/", html)  # evidence link
        self.assertIn("active", html)                 # open event status

    def test_non_admin_is_forbidden(self):
        resp = views.nd_events(_admin_request(admin=False))
        self.assertEqual(resp.status_code, 403)

    @mock.patch("dashboard.views.LookingGlassClient")
    def test_empty_when_no_events(self, MockLG):
        inst = MockLG.return_value
        inst.base_url = "http://lg"
        inst.get_nd_events.return_value = {"events": []}
        resp = views.nd_events(_admin_request())
        self.assertEqual(resp.status_code, 200)
        self.assertIn("No ND anomaly events recorded", resp.content.decode())


class NdEventCountEnrichmentTests(SimpleTestCase):
    def test_discovered_by_ip_attaches_event_count(self):
        lg = mock.Mock()
        lg.get_nd_events.return_value = {
            "events": [
                {"ip": "2001:db8:0:1::10"}, {"ip": "2001:db8:0:1::10"}, {"ip": "192.0.2.10"},
            ]
        }
        lg.get_discovered_neighbors.return_value = {
            "neighbors": [
                {"ip": "2001:db8:0:1::10", "conflict": True,
                 "macs": [{"mac": "a", "first_seen": "", "last_seen": ""}]},
                {"ip": "192.0.2.99", "conflict": False,
                 "macs": [{"mac": "b", "first_seen": "", "last_seen": ""}]},
            ]
        }
        out = views._fetch_discovered_by_ip(lg, "tok", 64496)
        self.assertEqual(out["2001:db8:0:1::10"]["event_count"], 2)
        self.assertEqual(out["192.0.2.99"]["event_count"], 0)
