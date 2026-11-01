import base64
import hashlib
import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import xml.etree.ElementTree as ET

from onvif_client import (
    DEVICE_NS,
    SOAP_NS,
    WSSE_NS,
    Device,
    build_soap_envelope,
    format_soap_response,
    get_services,
    infer_soap_action,
    load_devices,
    parse_services,
    save_devices,
    validate_endpoint,
)


class OnvifClientTests(unittest.TestCase):
    def test_device_service_url_supports_ipv4_and_ipv6(self) -> None:
        self.assertEqual(
            Device("camera", "192.0.2.10", port=8080).device_service_url,
            "http://192.0.2.10:8080/onvif/device_service",
        )
        self.assertEqual(
            Device("camera", "2001:db8::1", use_https=True).device_service_url,
            "https://[2001:db8::1]:80/onvif/device_service",
        )

    def test_digest_token_is_created_and_password_is_not_in_envelope(self) -> None:
        created = "2026-11-01T10:00:00Z"
        nonce = b"nonce-value"
        password = "not-in-the-request"
        xml = build_soap_envelope(
            f'<tds:GetDeviceInformation xmlns:tds="{DEVICE_NS}"/>',
            "operator",
            password,
            created=created,
            nonce=nonce,
        )
        root = ET.fromstring(xml)
        token = next(element for element in root.iter() if element.tag.endswith("UsernameToken"))
        values = {element.tag.rsplit("}", 1)[-1]: element.text for element in token}
        expected = base64.b64encode(
            hashlib.sha1(nonce + created.encode() + password.encode()).digest()
        ).decode()
        self.assertEqual(values["Username"], "operator")
        self.assertEqual(values["Password"], expected)
        self.assertEqual(values["Nonce"], base64.b64encode(nonce).decode())
        self.assertEqual(values["Created"], created)
        self.assertNotIn(password.encode(), xml)
        self.assertTrue(
            any(element.tag == f"{{{SOAP_NS}}}Body" for element in root.iter())
        )
        self.assertTrue(
            any(element.tag == f"{{{WSSE_NS}}}Security" for element in root.iter())
        )

    def test_action_inference_requires_namespace(self) -> None:
        self.assertEqual(
            infer_soap_action(
                f'<tds:GetServices xmlns:tds="{DEVICE_NS}"/>'
            ),
            f"{DEVICE_NS}/GetServices",
        )
        with self.assertRaisesRegex(ValueError, "declare its XML namespace"):
            infer_soap_action("<GetServices/>")

    def test_parse_services_extracts_service_details(self) -> None:
        xml = """\
        <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
                    xmlns:tds="http://www.onvif.org/ver10/device/wsdl"
                    xmlns:tt="http://www.onvif.org/ver10/schema">
          <s:Body><tds:GetServicesResponse>
            <tds:Service>
              <tds:Namespace>http://www.onvif.org/ver10/media/wsdl</tds:Namespace>
              <tds:XAddr>http://192.0.2.10/onvif/media_service</tds:XAddr>
              <tds:Version><tt:Major>2</tt:Major><tt:Minor>6</tt:Minor></tds:Version>
            </tds:Service>
          </tds:GetServicesResponse></s:Body>
        </s:Envelope>
        """
        services = parse_services(xml)
        self.assertEqual(len(services), 1)
        self.assertEqual(
            services[0].namespace, "http://www.onvif.org/ver10/media/wsdl"
        )
        self.assertEqual(services[0].xaddr, "http://192.0.2.10/onvif/media_service")
        self.assertEqual(services[0].version, "2.6")

    def test_format_device_information_removes_soap_and_labels_fields(self) -> None:
        response = f"""\
        <s:Envelope xmlns:s="{SOAP_NS}" xmlns:tds="{DEVICE_NS}">
          <s:Header><tds:Ignored>header</tds:Ignored></s:Header>
          <s:Body><tds:GetDeviceInformationResponse>
            <tds:Manufacturer>Example Cameras</tds:Manufacturer>
            <tds:Model>Model X</tds:Model>
            <tds:FirmwareVersion>1.2.3</tds:FirmwareVersion>
            <tds:SerialNumber>ABC123</tds:SerialNumber>
            <tds:HardwareId>HW-1</tds:HardwareId>
          </tds:GetDeviceInformationResponse></s:Body>
        </s:Envelope>
        """
        formatted = format_soap_response(response)
        self.assertEqual(
            formatted,
            "Manufacturer: Example Cameras\n"
            "Model: Model X\n"
            "Firmware version: 1.2.3\n"
            "Serial number: ABC123\n"
            "Hardware ID: HW-1",
        )
        self.assertNotIn("Envelope", formatted)
        self.assertNotIn("Header", formatted)

    def test_format_other_soap_responses_keeps_only_pretty_body_xml(self) -> None:
        response = f"""\
        <s:Envelope xmlns:s="{SOAP_NS}" xmlns:tds="{DEVICE_NS}">
          <s:Header/>
          <s:Body><tds:GetServicesResponse>
            <tds:Service><tds:XAddr>http://camera/service</tds:XAddr></tds:Service>
          </tds:GetServicesResponse></s:Body>
        </s:Envelope>
        """
        formatted = format_soap_response(response)
        self.assertIn("GetServicesResponse", formatted)
        self.assertIn("\n  ", formatted)
        self.assertNotIn("Envelope", formatted)
        self.assertNotIn("Header", formatted)

    def test_device_store_does_not_persist_password(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "devices.json"
            save_devices(
                [Device("front door", "192.0.2.10", username="admin", password="secret")],
                path,
            )
            stored = path.read_text(encoding="utf-8")
            self.assertNotIn("secret", stored)
            self.assertEqual(json.loads(stored)[0]["username"], "admin")
            loaded = load_devices(path)
            self.assertEqual(loaded[0].name, "front door")
            self.assertEqual(loaded[0].password, "")

    def test_get_services_sends_authenticated_soap_request(self) -> None:
        response_body = f"""\
        <s:Envelope xmlns:s="{SOAP_NS}" xmlns:tds="{DEVICE_NS}">
          <s:Body><tds:GetServicesResponse>
            <tds:Service>
              <tds:Namespace>http://www.onvif.org/ver10/device/wsdl</tds:Namespace>
              <tds:XAddr>http://127.0.0.1/device_service</tds:XAddr>
              <tds:Version><tds:Major>1</tds:Major><tds:Minor>0</tds:Minor></tds:Version>
            </tds:Service>
          </tds:GetServicesResponse></s:Body>
        </s:Envelope>
        """.encode()
        received: dict[str, str] = {}

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                body = self.rfile.read(int(self.headers["Content-Length"]))
                received["body"] = body.decode("utf-8")
                received["content_type"] = self.headers["Content-Type"]
                self.send_response(200)
                self.send_header("Content-Type", "application/soap+xml")
                self.send_header("Content-Length", str(len(response_body)))
                self.end_headers()
                self.wfile.write(response_body)

            def log_message(self, _format: str, *_args: object) -> None:
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            endpoint = f"http://127.0.0.1:{server.server_port}/onvif/device_service"
            response, services = get_services(endpoint, "admin", "secret")
        finally:
            server.shutdown()
            server.server_close()
            worker.join(timeout=2)

        self.assertEqual(response.status, 200)
        self.assertEqual(len(services), 1)
        self.assertIn(f'action="{DEVICE_NS}/GetServices"', received["content_type"])
        self.assertIn("GetServices", received["body"])
        self.assertIn("UsernameToken", received["body"])
        self.assertNotIn("secret", received["body"])

    def test_endpoint_rejects_embedded_credentials(self) -> None:
        with self.assertRaisesRegex(ValueError, "Do not include credentials"):
            validate_endpoint("http://user:pass@192.0.2.10/onvif/device_service")


if __name__ == "__main__":
    unittest.main()
