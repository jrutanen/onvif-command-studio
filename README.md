# ONVIF Command Studio

A small Python desktop client for registering ONVIF devices, discovering their
services with `GetServices`, and sending SOAP requests to the device or a
discovered service endpoint. Command templates cover Security, Uplink, ONVIF
WebRTC signaling, and cloud storage configuration renewal.

## Run

Requires Python 3.10+ with Tk installed. Create a virtual environment and
install dependencies into it (PowerShell):

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe app.py
```

If the Python launcher is unavailable, replace `py -3.12` with the path to
your Python 3.10+ interpreter. The application and tests should be run using
`.venv\Scripts\python.exe`; dependencies are installed in the virtual
environment, not globally. Tkinter is included with the standard Python
Windows installer and is not installed with pip.

Add a device using its host/IP, ONVIF port, username, and password. HTTP is
used by default; enable HTTPS when the device endpoint uses TLS. Select a device
and choose **Fetch services (GetServices)** to list its service namespaces,
endpoints, and versions. Double-click a service to use its endpoint for SOAP
requests.

The request editor accepts one XML operation element as the SOAP body. The
SOAP 1.2 envelope and WS-Security UsernameToken `PasswordDigest` header are
generated automatically. The SOAP action can be left blank to infer it from
the operation namespace and name. For example:

```xml
<tds:GetDeviceInformation
    xmlns:tds="http://www.onvif.org/ver10/device/wsdl"/>
```

The editor is generic rather than a generated command catalog: enter an
operation and namespace supported by the selected device/service. The template
menu provides ready-to-edit examples:

- **Security**: device-management user/certificate requests and Advanced
  Security capability, JWT, key, and certificate requests.
- **Uplink**: capability and configuration queries, plus editable set/delete
  examples.
- **WebRTC**: JSON-RPC `register`, `connect`, `extend`, and `unregister`
  messages sent over `wss://` using the `webrtc.onvif.org` WebSocket
  subprotocol. The app registers the connection before sending other methods.
- **Cloud Storage**: HTTPS `GET /Configuration-Renewal`, which returns the
  cloud service's storage configuration as JSON.

Select the matching service endpoint discovered by `GetServices` for Security
and Uplink SOAP templates. WebRTC and cloud templates require the actual
signaling/cloud service URL; replace the example URL before sending. Enter the
optional access token for WebRTC or cloud HTTP requests. It is sent using an
Authorization Bearer header and is not saved. WebRTC `connect`/`extend`
requests also include the token in their required JSON-RPC authorization
parameter. Use trusted HTTPS/WSS endpoints.

The **GetDeviceInformation** button loads a simple SOAP example.

Device name, host, port, username, and HTTPS preference are saved in the
current user's application-data directory. Passwords are kept in memory only
and are not written to disk; after restarting the application, enter the
password again before sending requests. HTTPS certificate verification is
enabled.

Run the unit tests with:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```
