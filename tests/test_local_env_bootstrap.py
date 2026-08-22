import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import scripts.bootstrap_local_env as bootstrap


class LocalEnvBootstrapTests(unittest.TestCase):
    def _template(self, root: Path) -> Path:
        path = root / ".env.example"
        path.write_text(
            "\n".join(
                [
                    "SMARTCAR_KEY_PROVIDER=environment",
                    "SMARTCAR_REQUIRE_HARDWARE_KEY_PROVIDER=0",
                    "SMARTCAR_PASSWORD=",
                    "SMARTCAR_AUTH_TOKEN=",
                    "SMARTCAR_VALIDATOR_KEY=",
                    "SMARTCAR_VEHICLE_ID=",
                    "SMARTCAR_ALLOW_INSECURE_SECRET_DEFAULTS=1",
                    "",
                ]
            ),
            encoding="utf-8",
        )
        return path

    @staticmethod
    def _values(path: Path):
        values = {}
        for line in path.read_text(encoding="utf-8").splitlines():
            key, value = bootstrap._split_assignment(line)
            if key is not None:
                values[key] = value
        return values

    def test_bootstrap_fills_all_managed_secrets_without_reuse(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            template = self._template(root)
            env_path = root / ".env"

            with patch.object(bootstrap, "TEMPLATE_PATH", template):
                generated, preserved = bootstrap.bootstrap_local_env(env_path)

            self.assertEqual(generated, len(bootstrap.MANAGED_SECRET_NAMES))
            self.assertEqual(preserved, 0)
            values = self._values(env_path)
            secrets = [values[name] for name in bootstrap.MANAGED_SECRET_NAMES]
            self.assertTrue(all(len(value) >= 32 for value in secrets))
            self.assertEqual(len(secrets), len(set(secrets)))
            self.assertEqual(values["SMARTCAR_ALLOW_INSECURE_SECRET_DEFAULTS"], "0")
            self.assertEqual(values["SMARTCAR_VEHICLE_ID"], "SMARTCAR_LOCAL_DEV_001")

    def test_bootstrap_preserves_existing_non_empty_credentials(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            template = self._template(root)
            env_path = root / ".env"
            existing_auth = "A" * 48
            env_path.write_text(
                "\n".join(
                    [
                        f"SMARTCAR_AUTH_TOKEN={existing_auth}",
                        "SMARTCAR_PASSWORD=",
                        "SMARTCAR_ALLOW_INSECURE_SECRET_DEFAULTS=1",
                        "",
                    ]
                ),
                encoding="utf-8",
            )

            with patch.object(bootstrap, "TEMPLATE_PATH", template):
                generated, preserved = bootstrap.bootstrap_local_env(env_path)

            values = self._values(env_path)
            self.assertEqual(values["SMARTCAR_AUTH_TOKEN"], existing_auth)
            self.assertEqual(generated, len(bootstrap.MANAGED_SECRET_NAMES) - 1)
            self.assertEqual(preserved, 1)
            self.assertEqual(values["SMARTCAR_ALLOW_INSECURE_SECRET_DEFAULTS"], "0")

    def test_rotate_all_replaces_existing_managed_credentials(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            template = self._template(root)
            env_path = root / ".env"
            existing_auth = "B" * 48
            env_path.write_text(f"SMARTCAR_AUTH_TOKEN={existing_auth}\n", encoding="utf-8")

            with patch.object(bootstrap, "TEMPLATE_PATH", template):
                generated, _ = bootstrap.bootstrap_local_env(env_path, rotate_all=True)

            values = self._values(env_path)
            self.assertEqual(generated, len(bootstrap.MANAGED_SECRET_NAMES))
            self.assertNotEqual(values["SMARTCAR_AUTH_TOKEN"], existing_auth)


if __name__ == "__main__":
    unittest.main()
