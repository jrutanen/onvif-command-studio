import json
import unittest
from unittest.mock import Mock, patch

from command_templates import COMMAND_TEMPLATES, TEMPLATES_BY_LABEL, UPLINK_NS
from onvif_client import (
    CommandResponse,
    infer_soap_action,
    send_http_get,
    send_websocket_json_rpc,
    validate_websocket_endpoint,
)


class CommandTemplateTests(unittest.TestCase):
    def test_templates_cover_requested_service_categories(self) -> None:
        categories = {template.category.split(" / ", 1)[0] for template in COMMAND_TEMPLATES}
        self.assertTrue({"Security", "Uplink", "WebRTC", "Cloud Storage"} <= categories)
        self.assertIn("Uplink - GetUplinks", TEMPLATES_BY_LABEL)
        self.assertIn("WebRTC / JSON-RPC - connect", TEMPLATES_BY_LABEL)
        uplink_set = TEMPLATES_BY_LABEL["Uplink - SetUplink"]
        self.assertEqual(uplink_set.action, f"{UPLINK_NS}/SetUplink")
        self.assertIn("RemoteAddress", uplink_set.body)
        for template in COMMAND_TEMPLATES:
            if template.transport == "SOAP":
                self.assertEqual(infer_soap_action(template.body), template.action)
            elif template.transport == "WebSocket":
                self.assertEqual(json.loads(template.body)["method"], template.name)

    def test_websocket_endpoint_requires_websocket_url(self) -> None:
        self.assertEqual(
            validate_websocket_endpoint("wss://signaling.example/"),
            "wss://signaling.example/",
        )
        with self.assertRaisesRegex(ValueError, "ws:// or wss://"):
            validate_websocket_endpoint("https://signaling.example/")


class TransportTests(unittest.TestCase):
    def test_http_get_sends_bearer_token_and_returns_json(self) -> None:
        response_context = Mock()
        response_context.status = 200
        response_context.read.return_value = b'{"storageUri":"https://bucket.example/"}'
        response_context.__enter__ = Mock(return_value=response_context)
        response_context.__exit__ = Mock(return_value=False)

        with patch(
            "onvif_client.urllib.request.urlopen", return_value=response_context
        ) as urlopen:
            response = send_http_get(
                "https://cloud.example/Configuration-Renewal", "test-token"
            )

        request = urlopen.call_args.args[0]
        self.assertEqual(request.get_method(), "GET")
        self.assertEqual(request.get_header("Authorization"), "Bearer test-token")
        self.assertIsInstance(response, CommandResponse)
        self.assertEqual(response.status, 200)
        self.assertEqual(json.loads(response.body)["storageUri"], "https://bucket.example/")

    def test_http_get_rejects_plain_http(self) -> None:
        with self.assertRaisesRegex(ValueError, "require an HTTPS"):
            send_http_get("http://cloud.example/Configuration-Renewal")

    def test_websocket_registers_then_sends_json_rpc(self) -> None:
        connection = Mock()
        connection.recv.side_effect = [
            '{"jsonrpc":"2.0","result":{"id":"client-1"},"id":"__onvif_register__"}',
            '{"jsonrpc":"2.0","result":{"session":"session-1"},"id":2}',
        ]
        request = json.dumps(
            {"jsonrpc": "2.0", "method": "connect", "params": {"peer": "camera-1"}, "id": 2}
        )

        with patch(
            "onvif_client.websocket.create_connection", return_value=connection
        ) as create_connection:
            response = send_websocket_json_rpc(
                "wss://signaling.example/", request, "test-token"
            )

        self.assertEqual(create_connection.call_args.kwargs["subprotocols"], ["webrtc.onvif.org"])
        self.assertTrue(
            any(
                header.startswith("Authorization: Bearer ")
                for header in create_connection.call_args.kwargs["header"]
            )
        )
        sent = [json.loads(call.args[0]) for call in connection.send.call_args_list]
        self.assertEqual(sent[0]["method"], "register")
        self.assertEqual(sent[1]["method"], "connect")
        self.assertEqual(sent[1]["params"]["authorization"], "test-token")
        self.assertEqual(json.loads(response.body)["result"]["session"], "session-1")
        connection.close.assert_called_once()

    def test_websocket_requires_tls_and_access_token(self) -> None:
        request = '{"jsonrpc":"2.0","method":"register","params":{},"id":1}'
        with self.assertRaisesRegex(ValueError, "requires an access token"):
            send_websocket_json_rpc("wss://signaling.example/", request)
        with self.assertRaisesRegex(ValueError, "wss://"):
            send_websocket_json_rpc("ws://signaling.example/", request, "token")

    def test_websocket_does_not_send_command_after_registration_error(self) -> None:
        connection = Mock()
        connection.recv.return_value = (
            '{"jsonrpc":"2.0","error":{"code":401,"message":"Unauthorized"},'
            '"id":"__onvif_register__"}'
        )
        request = '{"jsonrpc":"2.0","method":"connect","params":{},"id":2}'
        with patch(
            "onvif_client.websocket.create_connection", return_value=connection
        ):
            with self.assertRaisesRegex(RuntimeError, "registration failed"):
                send_websocket_json_rpc(
                    "wss://signaling.example/", request, "test-token"
                )

        self.assertEqual(connection.send.call_count, 1)
        connection.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
