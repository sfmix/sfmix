"""Unit tests for netbox_ix_lint's pure checks (synthetic data only).

    cd scripts && pipenv run python -m unittest test_netbox_ix_lint
"""
import unittest

from netbox_ix_lint import site_metadata_problems


def site(slug, site_id, status="active", **overrides):
    s = {
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
            "peeringdb_facility": 64512,
            "facility_operator": "Example Co",
            "mmr_operator": "Example Co",
            "mmr_portal_url": "https://example.net/",
        },
    }
    for key, value in overrides.items():
        if key in s["custom_fields"]:
            s["custom_fields"][key] = value
        else:
            s[key] = value
    return s


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

    def test_unnumbered_planned_site_and_placeholder_are_ignored(self):
        sites = [site("tst03", None, status="planned", group=None),
                 {"slug": "unassigned", "status": {"value": "planned"}, "custom_fields": {}}]
        self.assertEqual(site_metadata_problems(sites, []), [])

    def test_active_site_without_site_id(self):
        problems = site_metadata_problems([site("tst01", None)], [])
        self.assertIn(("tst01", "active site has no `site_id`"), problems)

    def test_duplicate_site_id(self):
        problems = site_metadata_problems([site("tst01", 9), site("tst02", 9, status="planned")], [])
        self.assertEqual(
            sorted(problems),
            [("tst01", "`site_id` 9 is shared with tst02"), ("tst02", "`site_id` 9 is shared with tst01")],
        )

    def test_peering_switch_at_unnumbered_site(self):
        sites = [site("tst01", 1), site("tst03", None, status="planned")]
        switches = [switch("switch01.tst03", "tst03"), switch("switch02.tst03", "tst03", status="decommissioning")]
        self.assertEqual(
            site_metadata_problems(sites, switches),
            [("tst03", "active peering switch switch01.tst03 is at a site without `site_id`")],
        )


if __name__ == "__main__":
    unittest.main()
