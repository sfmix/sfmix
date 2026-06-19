"""Unit tests for route-server parity computation."""

from django.test import SimpleTestCase

from dashboard.views import _compute_rs_parity, _parity_applicable, _real_routeservers

# Two configured route servers, mirroring production (BIRD + OpenBGPD).
ROUTESERVERS = [
    {"id": "rs1", "name": "RS1 (BIRD)"},
    {"id": "rs2", "name": "RS2 (OpenBGPD)"},
]


def _sess(rs_id, addr, state="established", accepted=100):
    return {
        "rs_id": rs_id,
        "rs_name": rs_id,
        "address": addr,
        "state": state,
        "routes_accepted": accepted,
    }


def _both_rs(v4_a1=100, v4_a2=100, v6_a1=50, v6_a2=50,
             v4_s1="established", v4_s2="established",
             v6_s1="established", v6_s2="established"):
    return [
        _sess("rs1", "192.0.2.10", v4_s1, v4_a1),
        _sess("rs1", "2001:db8::10", v6_s1, v6_a1),
        _sess("rs2", "192.0.2.10", v4_s2, v4_a2),
        _sess("rs2", "2001:db8::10", v6_s2, v6_a2),
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
        p = _compute_rs_parity(_both_rs(v4_a1=118, v4_a2=117), ROUTESERVERS)
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
        p = _compute_rs_parity(_both_rs(v4_a1=338, v4_a2=200), ROUTESERVERS)
        self.assertEqual(p["status"], "prefix_mismatch")
        self.assertEqual(p["severity"], "warn")
        self.assertEqual(p["sort_rank"], 2)

    def test_prefix_delta_under_pct_is_ok(self):
        # 1000 vs 996 → delta 4 (>2) but <10% → OK.
        p = _compute_rs_parity(_both_rs(v4_a1=1000, v4_a2=996), ROUTESERVERS)
        self.assertEqual(p["status"], "ok")

    def test_v4_only_participant_not_faulted_for_missing_v6(self):
        # Established v4 on both RS, no v6 anywhere → symmetric absence is OK.
        sessions = [
            _sess("rs1", "192.0.2.10"),
            _sess("rs2", "192.0.2.10"),
        ]
        p = _compute_rs_parity(sessions, ROUTESERVERS)
        self.assertEqual(p["status"], "ok")
        self.assertEqual(p["afs"], ["v4"])


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
