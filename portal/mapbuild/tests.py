"""mapbuild unit tests (synthetic data, no network)."""
from django.test import SimpleTestCase

from .peeringdb import RATE_LIMIT_RETRIES, PeeringDBClient


class FakeResponse:
    def __init__(self, status, data=None, headers=None):
        self.status_code = status
        self.headers = headers or {}
        self._data = data

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError("HTTP %d" % self.status_code)

    def json(self):
        return {"data": self._data or []}


class FakeSession:
    def __init__(self, responses):
        self.headers = {}
        self.responses = list(responses)
        self.paths = []

    def get(self, url, timeout=None):
        self.paths.append(url.rsplit("/api/", 1)[1])
        return self.responses.pop(0)


class PeeringDBClientTests(SimpleTestCase):
    def make(self, responses):
        self.sleeps = []
        session = FakeSession(responses)
        return PeeringDBClient(session=session, sleep=self.sleeps.append), session

    def test_waits_out_rate_limit_then_succeeds(self):
        fac = {"id": 64512, "name": "Example DC", "net_count": 3, "org_id": None}
        client, session = self.make([FakeResponse(429, headers={"Retry-After": "7"}),
                                    FakeResponse(200, [fac])])
        meta = client.facility_meta(64512)
        self.assertEqual(self.sleeps, [7])
        self.assertEqual(session.paths, ["fac/64512", "fac/64512"])
        self.assertEqual(meta["net_count"], 3)

    def test_gives_up_after_retries(self):
        client, session = self.make([FakeResponse(429)] * (RATE_LIMIT_RETRIES + 1))
        self.assertEqual(client.facility_meta(64512), {})
        self.assertEqual(self.sleeps, [60] * RATE_LIMIT_RETRIES)

    def test_retry_after_is_capped_and_floored(self):
        client, _ = self.make([FakeResponse(429, headers={"Retry-After": "3600"}),
                              FakeResponse(429, headers={"Retry-After": "0"}),
                              FakeResponse(200, [{"id": 1}])])
        client.facility(1)
        self.assertEqual(self.sleeps, [90, 1])

    def test_wait_budget_stops_retrying(self):
        # 60 + 60 spent on the first lookup; the second gets no more waiting
        client, session = self.make([FakeResponse(429), FakeResponse(429), FakeResponse(200, [{"id": 1}]),
                                     FakeResponse(429)])
        client.facility(1)
        self.assertEqual(client.facility_meta(2), {})
        self.assertEqual(self.sleeps, [60, 60])
        self.assertEqual(session.paths, ["fac/1", "fac/1", "fac/1", "fac/2"])

    def test_failed_lookup_falls_back_to_saved_cache(self):
        import json
        import os
        import tempfile
        path = os.path.join(tempfile.mkdtemp(), "pdb.json")
        fac = {"id": 64512, "name": "Example DC", "net_count": 3, "org_id": 7}
        org = {"id": 7, "logo": "https://example.net/logo.png"}
        first, _ = self.make([FakeResponse(200, [fac]), FakeResponse(200, [org])])
        first._cache_path = path
        self.assertEqual(first.facility_meta(64512)["logo"], org["logo"])
        first.save()
        self.assertEqual(set(json.load(open(path))), {"fac", "org"})

        self.sleeps = []
        second = PeeringDBClient(session=FakeSession([FakeResponse(500), FakeResponse(500)]),
                                 sleep=self.sleeps.append, cache_path=path)
        meta = second.facility_meta(64512)
        self.assertEqual(meta["net_count"], 3)
        self.assertEqual(meta["logo"], org["logo"])

    def test_lookups_are_memoised(self):
        client, session = self.make([FakeResponse(200, [{"id": 1}])])
        client.facility(1)
        client.facility(1)
        self.assertEqual(session.paths, ["fac/1"])
