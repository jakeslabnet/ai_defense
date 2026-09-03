import json
import os
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

import sender


class FakeResponse:
    status = 202

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self):
        return b"{}"


class SenderTests(unittest.TestCase):
    def test_each_rule_has_five_distinct_variants(self):
        self.assertGreaterEqual(len(sender.TEST_CASES), 1)
        for test_case in sender.TEST_CASES:
            self.assertEqual(len(test_case.content_templates), 5)
            self.assertEqual(len(set(test_case.content_templates)), 5)

    def test_payload_is_dynamic_and_labeled(self):
        payload = sender.build_payload(sender.TEST_CASES[:2])
        second_payload = sender.build_payload(sender.TEST_CASES[:2])
        self.assertEqual(list(payload), ["messages", "metadata", "config"])
        self.assertEqual(len(payload["messages"]), 2)
        self.assertEqual(payload["messages"][0]["role"], "user")
        self.assertIn("test", payload["messages"][0]["content"].lower())
        self.assertIn("Code Detection", sender.TEST_CASES[0].rule_name)
        self.assertNotEqual(
            payload["messages"][0]["content"],
            second_payload["messages"][0]["content"],
        )
        self.assertEqual(payload["metadata"], {})
        self.assertEqual(payload["config"], {})
        json.dumps(payload)

    def test_headers_include_defaults_and_overrides(self):
        headers = sender.load_headers('{"X-Test": "yes", "Content-Type": "custom"}', "secret")
        self.assertEqual(headers["X-Test"], "yes")
        self.assertEqual(headers["Content-Type"], "custom")
        self.assertEqual(headers["Accept"], "*/*")
        self.assertEqual(headers["Connection"], "keep-alive")
        self.assertEqual(headers["X-Cisco-AI-Defense-API-Key"], "secret")

    def test_invalid_headers_are_rejected(self):
        with self.assertRaises(ValueError):
            sender.load_headers("[]", None)

    def test_health_status_records_latest_response(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "health.json")
            with patch.dict(os.environ, {"HEALTH_STATUS_PATH": path}):
                payload = {"messages": [{"role": "user", "content": "test"}]}
                sender.record_health(200, payload=payload)
            state = json.loads(Path(path).read_text(encoding="utf-8"))
            self.assertEqual(state["status_code"], 200)
            self.assertEqual(state["last_payload"], payload)


    @patch("sender.time.sleep")
    @patch("sender.urllib.request.urlopen", return_value=FakeResponse())
    def test_once_sends_exactly_one_request(self, mock_urlopen, _mock_sleep):
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            os.environ,
            {"HEALTH_STATUS_PATH": os.path.join(directory, "health.json")},
        ):
            sender.run("https://example.test/events", 0, {}, 1, "sequential", once=True)
        self.assertEqual(mock_urlopen.call_count, 1)
        request = mock_urlopen.call_args.args[0]
        self.assertEqual(request.method, "POST")
        body = json.loads(request.data.decode("utf-8"))
        self.assertEqual(list(body), ["messages", "metadata", "config"])
        self.assertEqual(len(body["messages"]), 1)


if __name__ == "__main__":
    unittest.main()
