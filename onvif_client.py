"""Small standard-library ONVIF SOAP client helpers."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import ssl
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import websocket

SOAP_NS = "http://www.w3.org/2003/05/soap-envelope"
WSSE_NS = (
    "http://docs.oasis-open.org/wss/2004/01/"
    "oasis-200401-wss-wssecurity-secext-1.0.xsd"
)
WSU_NS = (
    "http://docs.oasis-open.org/wss/2004/01/"
    "oasis-200401-wss-wssecurity-utility-1.0.xsd"
)
DEVICE_NS = "http://www.onvif.org/ver10/device/wsdl"

ET.register_namespace("s", SOAP_NS)
ET.register_namespace("wsse", WSSE_NS)
ET.register_namespace("wsu", WSU_NS)


@dataclass
class Device:
    name: str
    host: str
    port: int = 80
    username: str = ""
    use_https: bool = False
    password: str = field(default="", repr=False, compare=False)

    @property
    def device_service_url(self) -> str:
        host = self.host.strip()
        if host.startswith("[") and host.endswith("]"):
            host = host[1:-1]
        if not host or any(char in host for char in "/?#@"):
            raise ValueError("Enter a host name or IP address, not a URL.")
        if ":" in host:
            host = f"[{host}]"
        scheme = "https" if self.use_https else "http"
        return f"{scheme}://{host}:{self.port}/onvif/device_service"


@dataclass(frozen=True)
class OnvifService:
    namespace: str
    xaddr: str
    version: str


@dataclass(frozen=True)
class CommandResponse:
    status: int
    body: str


def build_soap_envelope(
    body_xml: str,
    username: str,
    password: str,
    *,
    created: str | None = None,
    nonce: bytes | None = None,
) -> bytes:
    """Wrap one SOAP body element in SOAP 1.2 with WS-Security UsernameToken."""
    try:
        body_element = ET.fromstring(body_xml)
    except ET.ParseError as exc:
        raise ValueError(f"Invalid XML body: {exc}") from exc

    envelope = ET.Element(f"{{{SOAP_NS}}}Envelope")
    header = ET.SubElement(envelope, f"{{{SOAP_NS}}}Header")
    security = ET.SubElement(
        header,
        f"{{{WSSE_NS}}}Security",
        {f"{{{SOAP_NS}}}mustUnderstand": "true"},
    )
    token = ET.SubElement(security, f"{{{WSSE_NS}}}UsernameToken")
    ET.SubElement(token, f"{{{WSSE_NS}}}Username").text = username

    created = created or datetime.now(timezone.utc).isoformat(
        timespec="seconds"
    ).replace("+00:00", "Z")
    nonce = nonce if nonce is not None else secrets.token_bytes(20)
    digest = hashlib.sha1(nonce + created.encode("utf-8") + password.encode("utf-8"))
    password_digest = base64.b64encode(digest.digest()).decode("ascii")
    ET.SubElement(
        token,
        f"{{{WSSE_NS}}}Password",
        {
            "Type": (
                "http://docs.oasis-open.org/wss/2004/01/"
                "oasis-200401-wss-username-token-profile-1.0#PasswordDigest"
            )
        },
    ).text = password_digest
    ET.SubElement(
        token,
        f"{{{WSSE_NS}}}Nonce",
        {
            "EncodingType": (
                "http://docs.oasis-open.org/wss/2004/01/"
                "oasis-200401-wss-soap-message-security-1.0#Base64Binary"
            )
        },
    ).text = base64.b64encode(nonce).decode("ascii")
    ET.SubElement(token, f"{{{WSU_NS}}}Created").text = created

    soap_body = ET.SubElement(envelope, f"{{{SOAP_NS}}}Body")
    soap_body.append(body_element)
    return ET.tostring(envelope, encoding="utf-8", xml_declaration=True)


def infer_soap_action(body_xml: str) -> str:
    """Infer an ONVIF SOAP action from the body element's namespace and name."""
    try:
        operation = ET.fromstring(body_xml)
    except ET.ParseError as exc:
        raise ValueError(f"Invalid XML body: {exc}") from exc
    if not operation.tag.startswith("{"):
        raise ValueError("The SOAP body operation must declare its XML namespace.")
    namespace, local_name = operation.tag[1:].split("}", 1)
    if not namespace or not local_name:
        raise ValueError("Could not infer a SOAP action from the body operation.")
    return f"{namespace}/{local_name}"


def validate_endpoint(endpoint: str) -> str:
    endpoint = endpoint.strip()
    parsed = urlsplit(endpoint)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Service endpoint must be an absolute HTTP or HTTPS URL.")
    if parsed.username or parsed.password:
        raise ValueError("Do not include credentials in the service endpoint URL.")
    return endpoint


def send_soap(
    endpoint: str,
    body_xml: str,
    username: str,
    password: str,
    *,
    soap_action: str = "",
    timeout: float = 10,
) -> CommandResponse:
    endpoint = validate_endpoint(endpoint)
    action = soap_action.strip() or infer_soap_action(body_xml)
    envelope = build_soap_envelope(body_xml, username, password)

    headers = {"Content-Type": "application/soap+xml; charset=utf-8"}
    if action:
        headers["Content-Type"] += f'; action="{action}"'
    request = urllib.request.Request(
        endpoint,
        data=envelope,
        headers=headers,
        method="POST",
    )

    password_manager = urllib.request.HTTPPasswordMgrWithDefaultRealm()
    password_manager.add_password(None, endpoint, username, password)
    opener = urllib.request.build_opener(
        urllib.request.HTTPDigestAuthHandler(password_manager)
    )
    if endpoint.startswith("https://"):
        opener.add_handler(urllib.request.HTTPSHandler(context=ssl.create_default_context()))

    try:
        with opener.open(request, timeout=timeout) as response:
            response_body = response.read().decode("utf-8", errors="replace")
            return CommandResponse(response.status, response_body)
    except urllib.error.HTTPError as exc:
        response_body = exc.read().decode("utf-8", errors="replace")
        return CommandResponse(exc.code, response_body)


def get_services(
    device_service_url: str,
    username: str,
    password: str,
    *,
    timeout: float = 10,
) -> tuple[CommandResponse, list[OnvifService]]:
    body = (
        f'<tds:GetServices xmlns:tds="{DEVICE_NS}">'
        "<tds:IncludeCapability>false</tds:IncludeCapability>"
        "</tds:GetServices>"
    )
    action = f"{DEVICE_NS}/GetServices"
    response = send_soap(
        device_service_url,
        body,
        username,
        password,
        soap_action=action,
        timeout=timeout,
    )
    if not 200 <= response.status < 300:
        raise RuntimeError(
            f"GetServices returned HTTP {response.status}:\n{response.body}"
        )
    return response, parse_services(response.body)


def validate_websocket_endpoint(endpoint: str) -> str:
    endpoint = endpoint.strip()
    parsed = urlsplit(endpoint)
    if parsed.scheme not in {"ws", "wss"} or not parsed.hostname:
        raise ValueError("WebSocket endpoint must be an absolute ws:// or wss:// URL.")
    if parsed.username or parsed.password:
        raise ValueError("Do not include credentials in the WebSocket endpoint URL.")
    return endpoint


def send_http_get(
    endpoint: str,
    access_token: str = "",
    *,
    timeout: float = 10,
) -> CommandResponse:
    endpoint = validate_endpoint(endpoint)
    if not endpoint.startswith("https://"):
        raise ValueError("Cloud storage requests require an HTTPS endpoint.")
    headers = {"Accept": "application/json"}
    if access_token.strip():
        headers["Authorization"] = f"Bearer {access_token.strip()}"
    request = urllib.request.Request(endpoint, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            response_body = response.read().decode("utf-8", errors="replace")
            return CommandResponse(response.status, response_body)
    except urllib.error.HTTPError as exc:
        response_body = exc.read().decode("utf-8", errors="replace")
        return CommandResponse(exc.code, response_body)


def _read_json_rpc_response(
    connection: websocket.WebSocket, request_id: object
) -> dict[str, object]:
    while True:
        message = connection.recv()
        if not isinstance(message, str):
            raise RuntimeError("WebRTC signaling server returned a non-text message.")
        try:
            response = json.loads(message)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"WebRTC server returned invalid JSON: {exc}") from exc
        if isinstance(response, dict) and response.get("id") == request_id:
            return response


def send_websocket_json_rpc(
    endpoint: str,
    body: str,
    access_token: str = "",
    *,
    timeout: float = 10,
) -> CommandResponse:
    endpoint = validate_websocket_endpoint(endpoint)
    try:
        request = json.loads(body)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid WebRTC JSON-RPC request: {exc}") from exc
    if not isinstance(request, dict) or request.get("jsonrpc") != "2.0":
        raise ValueError('WebRTC request must be a JSON object with "jsonrpc": "2.0".')
    method = request.get("method")
    request_id = request.get("id")
    if not isinstance(method, str) or not method:
        raise ValueError('WebRTC request must include a non-empty "method".')
    if request_id is None:
        raise ValueError("WebRTC request must include an id to match its response.")

    token = access_token.strip()
    if not token:
        raise ValueError("ONVIF WebRTC signaling requires an access token.")
    if not endpoint.startswith("wss://"):
        raise ValueError("Use a wss:// WebRTC endpoint to protect the access token.")
    params = request.get("params")
    if token and isinstance(params, dict) and method in {"register", "connect", "extend"}:
        params["authorization"] = token

    headers = [f"Authorization: Bearer {token}"] if token else []
    try:
        connection = websocket.create_connection(
            endpoint,
            timeout=timeout,
            subprotocols=["webrtc.onvif.org"],
            header=headers,
        )
    except websocket.WebSocketException as exc:
        raise RuntimeError(f"Could not connect to WebRTC signaling server: {exc}") from exc

    try:
        if method != "register":
            register_id = "__onvif_register__"
            connection.send(
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "method": "register",
                        "params": {},
                        "id": register_id,
                    }
                )
            )
            register_response = _read_json_rpc_response(connection, register_id)
            if "error" in register_response:
                raise RuntimeError(
                    "WebRTC registration failed: "
                    + json.dumps(register_response["error"], ensure_ascii=False)
                )
        connection.send(json.dumps(request))
        response = _read_json_rpc_response(connection, request_id)
        return CommandResponse(
            101, json.dumps(response, indent=2, ensure_ascii=False)
        )
    except websocket.WebSocketException as exc:
        raise RuntimeError(f"WebRTC signaling request failed: {exc}") from exc
    finally:
        connection.close()


def parse_services(response_xml: str) -> list[OnvifService]:
    try:
        root = ET.fromstring(response_xml)
    except ET.ParseError as exc:
        raise ValueError(f"Invalid GetServices response XML: {exc}") from exc

    services: list[OnvifService] = []
    for service in root.iter():
        if service.tag.rsplit("}", 1)[-1] != "Service":
            continue
        children = {child.tag.rsplit("}", 1)[-1]: child for child in service}
        values = {
            name: (element.text or "").strip()
            for name, element in children.items()
        }
        if values.get("Namespace") and values.get("XAddr"):
            version_element = children.get("Version")
            version = values.get("Version", "")
            if version_element is not None and len(version_element):
                version_parts = {
                    child.tag.rsplit("}", 1)[-1]: (child.text or "").strip()
                    for child in version_element
                }
                major = version_parts.get("Major", "")
                minor = version_parts.get("Minor", "")
                version = ".".join(part for part in (major, minor) if part)
            services.append(
                OnvifService(
                    namespace=values["Namespace"],
                    xaddr=values["XAddr"],
                    version=version,
                )
            )
    return services


def format_soap_response(response_xml: str) -> str:
    """Remove the SOAP envelope and render ONVIF response content for display."""
    try:
        root = ET.fromstring(response_xml)
    except ET.ParseError:
        return response_xml

    soap_body = next(
        (
            element
            for element in root.iter()
            if element.tag == f"{{{SOAP_NS}}}Body"
        ),
        None,
    )
    if soap_body is None:
        payload = root
    elif len(soap_body) == 1:
        payload = soap_body[0]
    else:
        payload = soap_body

    if payload.tag.rsplit("}", 1)[-1] == "GetDeviceInformationResponse":
        labels = {
            "Manufacturer": "Manufacturer",
            "Model": "Model",
            "FirmwareVersion": "Firmware version",
            "SerialNumber": "Serial number",
            "HardwareId": "Hardware ID",
        }
        fields = []
        for field_name, label in labels.items():
            value = next(
                (
                    " ".join(part.strip() for part in element.itertext() if part.strip())
                    for element in payload
                    if element.tag.rsplit("}", 1)[-1] == field_name
                ),
                "",
            )
            if value:
                fields.append(f"{label}: {value}")
        return "\n".join(fields) if fields else "Device returned no information."

    ET.indent(payload, space="  ")
    return ET.tostring(payload, encoding="unicode")


def device_store_path() -> Path:
    app_data = os.environ.get("APPDATA")
    base = Path(app_data) if app_data else Path.home() / ".config"
    return base / "OnvifCommandStudio" / "devices.json"


def load_devices(path: Path | None = None) -> list[Device]:
    store = path or device_store_path()
    if not store.exists():
        return []
    try:
        raw_devices = json.loads(store.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Could not read saved device list {store}: {exc}") from exc
    if not isinstance(raw_devices, list):
        raise RuntimeError(f"Saved device list {store} must contain a JSON array.")

    devices: list[Device] = []
    try:
        for item in raw_devices:
            if not isinstance(item, dict):
                raise ValueError("Each saved device must be a JSON object.")
            devices.append(
                Device(
                    name=str(item["name"]),
                    host=str(item["host"]),
                    port=int(item.get("port", 80)),
                    username=str(item.get("username", "")),
                    use_https=bool(item.get("use_https", False)),
                )
            )
    except (KeyError, TypeError, ValueError) as exc:
        raise RuntimeError(f"Saved device list {store} contains invalid data: {exc}") from exc
    return devices


def save_devices(devices: list[Device], path: Path | None = None) -> None:
    """Persist device metadata only; passwords are intentionally session-only."""
    store = path or device_store_path()
    records = [
        {
            "name": device.name,
            "host": device.host,
            "port": device.port,
            "username": device.username,
            "use_https": device.use_https,
        }
        for device in devices
    ]
    try:
        store.parent.mkdir(parents=True, exist_ok=True)
        store.write_text(json.dumps(records, indent=2), encoding="utf-8")
    except OSError as exc:
        raise RuntimeError(f"Could not save device list {store}: {exc}") from exc
