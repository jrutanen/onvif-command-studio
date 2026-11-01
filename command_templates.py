"""Editable ONVIF and related service command templates."""

from dataclasses import dataclass

DEVICE_NS = "http://www.onvif.org/ver10/device/wsdl"
ADVANCED_SECURITY_NS = "http://www.onvif.org/ver10/advancedsecurity/wsdl"
UPLINK_NS = "http://www.onvif.org/ver10/uplink/wsdl"
STORAGE_RENEWAL_URL = "https://cloud-service.example/Configuration-Renewal"
WEBRTC_URL = "wss://signaling-server.example/"
WEBRTC_REGISTER = (
    '{"jsonrpc":"2.0","method":"register","params":{},"id":1}'
)


@dataclass(frozen=True)
class CommandTemplate:
    name: str
    category: str
    transport: str
    body: str
    endpoint: str = ""
    namespace: str = ""
    action: str = ""
    description: str = ""

    @property
    def label(self) -> str:
        return f"{self.category} - {self.name}"


def _soap_template(
    category: str,
    operation: str,
    namespace: str,
    *,
    body: str | None = None,
    description: str = "",
) -> CommandTemplate:
    operation_body = body or f'<op:{operation} xmlns:op="{namespace}"/>'
    return CommandTemplate(
        name=operation,
        category=category,
        transport="SOAP",
        body=operation_body,
        namespace=namespace,
        action=f"{namespace}/{operation}",
        description=description,
    )


COMMAND_TEMPLATES = (
    _soap_template("Security / Device", "GetUsers", DEVICE_NS),
    _soap_template("Security / Device", "GetCertificates", DEVICE_NS),
    _soap_template("Security / Device", "GetCACertificates", DEVICE_NS),
    _soap_template("Security / Advanced", "GetServiceCapabilities", ADVANCED_SECURITY_NS),
    _soap_template("Security / Advanced", "GetJWTConfiguration", ADVANCED_SECURITY_NS),
    _soap_template("Security / Advanced", "GetAllKeys", ADVANCED_SECURITY_NS),
    _soap_template("Security / Advanced", "GetAllCertificates", ADVANCED_SECURITY_NS),
    _soap_template("Uplink", "GetServiceCapabilities", UPLINK_NS),
    _soap_template("Uplink", "GetUplinks", UPLINK_NS),
    _soap_template(
        "Uplink",
        "SetUplink",
        UPLINK_NS,
        body=(
            f'<tup:SetUplink xmlns:tup="{UPLINK_NS}">'
            "<tup:Configuration>"
            "<tup:RemoteAddress>https://uplink-server.example/</tup:RemoteAddress>"
            "<tup:UserLevel>Administrator</tup:UserLevel>"
            "</tup:Configuration></tup:SetUplink>"
        ),
        description="Adds or updates an uplink configuration; edit the sample address and role.",
    ),
    _soap_template(
        "Uplink",
        "DeleteUplink",
        UPLINK_NS,
        body=(
            f'<tup:DeleteUplink xmlns:tup="{UPLINK_NS}">'
            "<tup:RemoteAddress>https://uplink-server.example/</tup:RemoteAddress>"
            "</tup:DeleteUplink>"
        ),
        description="Removes the uplink configuration for the specified remote address.",
    ),
    CommandTemplate(
        name="register",
        category="WebRTC / JSON-RPC",
        transport="WebSocket",
        endpoint=WEBRTC_URL,
        body=WEBRTC_REGISTER,
        description="Registers this client with the ONVIF WebRTC signaling server.",
    ),
    CommandTemplate(
        name="connect",
        category="WebRTC / JSON-RPC",
        transport="WebSocket",
        endpoint=WEBRTC_URL,
        body=(
            '{"jsonrpc":"2.0","method":"connect","params":'
            '{"peer":"<peer-id>"},"id":2}'
        ),
        description="Starts a session with a peer; replace the peer ID and provide an access token above.",
    ),
    CommandTemplate(
        name="extend",
        category="WebRTC / JSON-RPC",
        transport="WebSocket",
        endpoint=WEBRTC_URL,
        body=(
            '{"jsonrpc":"2.0","method":"extend","params":'
            '{"session":"<session-id>"},"id":2}'
        ),
        description="Extends a session; replace the session ID and provide an access token above.",
    ),
    CommandTemplate(
        name="unregister",
        category="WebRTC / JSON-RPC",
        transport="WebSocket",
        endpoint=WEBRTC_URL,
        body='{"jsonrpc":"2.0","method":"unregister","params":{},"id":2}',
        description="Unregisters the client before intentionally closing its connection.",
    ),
    CommandTemplate(
        name="GET Configuration-Renewal",
        category="Cloud Storage / HTTP JSON",
        transport="HTTP GET",
        endpoint=STORAGE_RENEWAL_URL,
        body="",
        description=(
            "Fetches storage configuration renewal JSON from the cloud service. "
            "Replace the example URL."
        ),
    ),
)

TEMPLATES_BY_LABEL = {template.label: template for template in COMMAND_TEMPLATES}
