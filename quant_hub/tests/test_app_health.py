from __future__ import annotations

from quant_hub.app import create_app
from quant_hub.runtime_seal import file_identity
from tests.helpers import SettingsTestCase


class HealthProbeTests(SettingsTestCase):
    def test_health_probe_does_not_initialize_lazy_business_databases(self) -> None:
        app = create_app(self.settings, {"TESTING": True})
        self.assertFalse(self.settings.research_papers_database_path.exists())
        self.assertTrue(self.settings.paper_lab_database_path.exists())
        paper_lab_before = file_identity(self.settings.paper_lab_database_path)
        with app.test_client() as client:
            response = client.get("/healthz")
        self.assertEqual(200, response.status_code)
        self.assertEqual(
            {
                "schema_version": "qrh-health/v1",
                "service": "quant-research-hub",
                "status": "ok",
            },
            response.get_json(),
        )
        self.assertEqual("no-store", response.headers["Cache-Control"])
        self.assertFalse(self.settings.research_papers_database_path.exists())
        self.assertEqual(
            paper_lab_before, file_identity(self.settings.paper_lab_database_path)
        )


if __name__ == "__main__":
    import unittest

    unittest.main()
