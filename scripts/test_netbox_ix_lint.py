"""Unit tests for netbox_ix_lint's pure checks (synthetic data only).

    cd scripts && pipenv run python -m unittest test_netbox_ix_lint
"""
import unittest

from netbox_ix_lint import site_metadata_problems


def site(slug, site_id, status="active", presence="peering", pk=None, **overrides):
    s = {
        "id": pk if pk is not None else (site_id if site_id is not None else 1000 + sum(map(ord, slug))),
        "slug": slug,
        "status": {"value": status, "label": status.title()},
        "region": {"name": "Exampleville"},
        "group": {"name": "Example Metro"},
        "description": f"{slug} display name",
        "facility": "Example DC",
        "physical_address": "1 Example Way\r\nExampleville, CA 90000",
        "latitude": 37.5,
        "longitude": -122.1,
        "custom_fields": {
            "site_id": site_id,
            "sfmix_presence": presence,
            "cross_connect_from": [],
            "peeringdb_facility": 64512,
            "facility_operator": "Example Co",
            "mmr_portal_url": "https://example.net/",
        },
    }
    for key, value in overrides.items():
        if key in s["custom_fields"]:
            s["custom_fields"][key] = value
        else:
            s[key] = value
    return s


def reach(slug, pk, site_id=None, **overrides):
    return site(slug, site_id, presence="cross_connect", pk=pk, peeringdb_facility=None,
                mmr_portal_url=None, **overrides)


def switch(name, site_slug, status="active"):
    return {"name": name, "status": {"value": status}, "site": {"slug": site_slug}}


class SiteMetadataTests(unittest.TestCase):
    def test_complete_sites_pass(self):
        sites = [site("tst01", 1), site("tst02", 2, status="planned")]
        self.assertEqual(site_metadata_problems(sites, [switch("switch01.tst01", "tst01")]), [])

    def test_missing_fields_are_listed(self):
        sites = [site("tst01", 1, group=None, mmr_portal_url="", latitude=None)]
        [(slug, message)] = site_metadata_problems(sites, [])
        self.assertEqual(slug, "tst01")
        self.assertIn("site group (metro)", message)
        self.assertIn("mmr_portal_url", message)
        self.assertIn("latitude", message)

    def test_unclassified_planned_site_and_placeholder_are_ignored(self):
        sites = [site("tst03", None, status="planned", presence=None, group=None),
                 {"slug": "unassigned", "status": {"value": "planned"}, "custom_fields": {}}]
        self.assertEqual(site_metadata_problems(sites, []), [])

    def test_active_or_numbered_site_without_presence(self):
        problems = site_metadata_problems(
            [site("tst01", None, presence=None), site("tst02", 2, status="planned", presence=None)], [])
        self.assertEqual(sorted(problems), [("tst01", "site has no `sfmix_presence`"),
                                            ("tst02", "site has no `sfmix_presence`")])

    def test_peering_site_without_site_id(self):
        problems = site_metadata_problems([site("tst01", None)], [])
        self.assertIn(("tst01", "peering site has no `site_id`"), problems)

    def test_duplicate_site_id(self):
        problems = site_metadata_problems([site("tst01", 9), site("tst02", 9, status="planned", pk=10)], [])
        self.assertEqual(
            sorted(problems),
            [("tst01", "`site_id` 9 is shared with tst02"), ("tst02", "`site_id` 9 is shared with tst01")],
        )

    def test_peering_switch_at_unnumbered_site(self):
        sites = [site("tst01", 1), site("tst03", None, status="planned", presence=None)]
        switches = [switch("switch01.tst03", "tst03"), switch("switch02.tst03", "tst03", status="decommissioning")]
        self.assertEqual(
            site_metadata_problems(sites, switches),
            [("tst03", "active peering switch switch01.tst03 is at a site without `site_id`")],
        )

    def test_linked_cross_connect_site_passes(self):
        sites = [site("tst01", 1, cross_connect_from=[{"id": 501}]), reach("example-ex2", 501)]
        self.assertEqual(site_metadata_problems(sites, []), [])

    def test_unlinked_cross_connect_site(self):
        problems = site_metadata_problems([site("tst01", 1), reach("example-ex2", 501)], [])
        self.assertEqual(problems, [("example-ex2", "cross_connect site isn't in any peering site's `cross_connect_from`")])

    def test_cross_connect_site_needs_location_but_not_portal(self):
        sites = [site("tst01", 1, cross_connect_from=[501]), reach("example-ex2", 501, latitude=None)]
        self.assertEqual(site_metadata_problems(sites, []), [("example-ex2", "missing latitude")])

    def test_cross_connect_site_with_site_id(self):
        sites = [site("tst01", 1, cross_connect_from=[501]), reach("example-ex2", 501, site_id=7)]
        self.assertEqual(site_metadata_problems(sites, []), [("example-ex2", "cross_connect site has a `site_id`")])

    def test_peering_site_links_a_peering_site(self):
        sites = [site("tst01", 1, cross_connect_from=[{"id": 2}]), site("tst02", 2)]
        self.assertEqual(site_metadata_problems(sites, []),
                         [("tst01", "`cross_connect_from` links tst02, which isn't a cross_connect site")])

    def test_presence_as_choice_object(self):
        sites = [site("tst01", 1, sfmix_presence={"value": "peering", "label": "Peering"})]
        self.assertEqual(site_metadata_problems(sites, []), [])


if __name__ == "__main__":
    unittest.main()
