from __future__ import annotations

import json
import queue
import threading
import tkinter as tk
from collections.abc import Callable
from tkinter import messagebox, ttk

from onvif_client import (
    CommandResponse,
    DEVICE_NS,
    Device,
    OnvifService,
    format_soap_response,
    get_services,
    infer_soap_action,
    load_devices,
    save_devices,
    send_soap,
    send_http_get,
    send_websocket_json_rpc,
    validate_endpoint,
    validate_websocket_endpoint,
)
from command_templates import (
    COMMAND_TEMPLATES,
    CommandTemplate,
    TEMPLATES_BY_LABEL,
)

RequestResult = CommandResponse | tuple[CommandResponse, list[OnvifService]]


class OnvifCommandStudio:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("ONVIF Command Studio")
        self.root.geometry("1100x780")
        self.devices: list[Device] = []
        self.services: list[OnvifService] = []
        self.results: queue.Queue[tuple[str, RequestResult | Exception, bool]] = (
            queue.Queue()
        )
        self.busy = False

        self._build_ui()
        try:
            self.devices = load_devices()
        except RuntimeError as exc:
            messagebox.showerror("Saved devices", str(exc), parent=self.root)
        self._refresh_devices()
        self.root.after(100, self._poll_results)

    def _build_ui(self) -> None:
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        layout = ttk.Panedwindow(self.root, orient=tk.HORIZONTAL)
        layout.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)

        device_panel = ttk.Frame(layout, padding=8)
        command_panel = ttk.Frame(layout, padding=8)
        layout.add(device_panel, weight=1)
        layout.add(command_panel, weight=4)
        self._build_device_panel(device_panel)
        self._build_command_panel(command_panel)

        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(self.root, textvariable=self.status_var, anchor="w").grid(
            row=1, column=0, sticky="ew", padx=12, pady=(0, 8)
        )

    def _build_device_panel(self, parent: ttk.Frame) -> None:
        parent.columnconfigure(0, weight=1)
        ttk.Label(parent, text="ONVIF devices", font=("", 12, "bold")).grid(
            row=0, column=0, sticky="w", pady=(0, 8)
        )
        ttk.Label(parent, text="Name").grid(row=1, column=0, sticky="w")
        self.name_var = tk.StringVar()
        ttk.Entry(parent, textvariable=self.name_var).grid(
            row=2, column=0, sticky="ew", pady=(0, 6)
        )

        ttk.Label(parent, text="IP address / host").grid(row=3, column=0, sticky="w")
        self.host_var = tk.StringVar()
        ttk.Entry(parent, textvariable=self.host_var).grid(
            row=4, column=0, sticky="ew", pady=(0, 6)
        )

        connection = ttk.Frame(parent)
        connection.grid(row=5, column=0, sticky="ew")
        connection.columnconfigure(1, weight=1)
        ttk.Label(connection, text="Port").grid(row=0, column=0, sticky="w")
        self.port_var = tk.StringVar(value="80")
        ttk.Entry(connection, textvariable=self.port_var, width=8).grid(
            row=0, column=1, sticky="w", padx=(6, 0)
        )
        self.https_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            connection,
            text="HTTPS",
            variable=self.https_var,
            command=self._update_device_endpoint,
        ).grid(row=0, column=2, sticky="e")

        ttk.Label(parent, text="Username").grid(row=6, column=0, sticky="w", pady=(6, 0))
        self.username_var = tk.StringVar()
        ttk.Entry(parent, textvariable=self.username_var).grid(
            row=7, column=0, sticky="ew", pady=(0, 6)
        )
        ttk.Label(parent, text="Password (session only)").grid(
            row=8, column=0, sticky="w"
        )
        self.password_var = tk.StringVar()
        ttk.Entry(parent, textvariable=self.password_var, show="*").grid(
            row=9, column=0, sticky="ew", pady=(0, 8)
        )

        buttons = ttk.Frame(parent)
        buttons.grid(row=10, column=0, sticky="ew", pady=(0, 10))
        ttk.Button(buttons, text="Add device", command=self._add_device).pack(
            side=tk.LEFT, fill=tk.X, expand=True
        )
        ttk.Button(buttons, text="Remove", command=self._remove_device).pack(
            side=tk.LEFT, fill=tk.X, expand=True, padx=(6, 0)
        )

        ttk.Label(parent, text="Saved devices").grid(row=11, column=0, sticky="w")
        self.device_list = tk.Listbox(parent, height=12, exportselection=False)
        self.device_list.grid(row=12, column=0, sticky="nsew", pady=(4, 0))
        parent.rowconfigure(12, weight=1)
        self.device_list.bind("<<ListboxSelect>>", self._device_selected)
        ttk.Label(
            parent,
            text="Passwords stay in memory and are not written to the device list.",
            wraplength=230,
            justify=tk.LEFT,
        ).grid(row=13, column=0, sticky="w", pady=(8, 0))

    def _build_command_panel(self, parent: ttk.Frame) -> None:
        parent.columnconfigure(0, weight=1)
        parent.rowconfigure(1, weight=1)
        parent.rowconfigure(10, weight=2)
        parent.rowconfigure(11, weight=2)

        service_header = ttk.Frame(parent)
        service_header.grid(row=0, column=0, sticky="ew")
        service_header.columnconfigure(0, weight=1)
        ttk.Label(
            service_header, text="Services on selected device", font=("", 12, "bold")
        ).grid(row=0, column=0, sticky="w")
        self.fetch_button = ttk.Button(
            service_header, text="Fetch services (GetServices)", command=self._fetch_services
        )
        self.fetch_button.grid(row=0, column=1, sticky="e")

        tree_frame = ttk.Frame(parent)
        tree_frame.grid(row=1, column=0, sticky="nsew", pady=(6, 10))
        tree_frame.columnconfigure(0, weight=1)
        tree_frame.rowconfigure(0, weight=1)
        self.service_tree = ttk.Treeview(
            tree_frame,
            columns=("namespace", "endpoint", "version"),
            show="headings",
            height=6,
        )
        for column, title, width in (
            ("namespace", "Namespace", 270),
            ("endpoint", "Service endpoint", 360),
            ("version", "Version", 90),
        ):
            self.service_tree.heading(column, text=title)
            self.service_tree.column(column, width=width, minwidth=100, stretch=True)
        self.service_tree.grid(row=0, column=0, sticky="nsew")
        scrollbar = ttk.Scrollbar(
            tree_frame, orient=tk.VERTICAL, command=self.service_tree.yview
        )
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.service_tree.configure(yscrollcommand=scrollbar.set)
        self.service_tree.bind("<Double-1>", self._use_selected_service)

        ttk.Label(parent, text="Request endpoint").grid(row=2, column=0, sticky="w")
        self.endpoint_var = tk.StringVar()
        ttk.Entry(parent, textvariable=self.endpoint_var).grid(
            row=3, column=0, sticky="ew", pady=(3, 8)
        )

        template_row = ttk.Frame(parent)
        template_row.grid(row=4, column=0, sticky="ew", pady=(0, 6))
        template_row.columnconfigure(1, weight=1)
        ttk.Label(template_row, text="Command template").grid(
            row=0, column=0, sticky="w", padx=(0, 8)
        )
        self.template_var = tk.StringVar(value="Custom SOAP")
        self.template_combo = ttk.Combobox(
            template_row,
            textvariable=self.template_var,
            values=["Custom SOAP", *(template.label for template in COMMAND_TEMPLATES)],
            state="readonly",
        )
        self.template_combo.grid(row=0, column=1, sticky="ew")
        self.template_combo.bind("<<ComboboxSelected>>", self._template_selected)

        ttk.Label(parent, text="Optional access token (WebRTC / cloud HTTP)").grid(
            row=5, column=0, sticky="w"
        )
        self.access_token_var = tk.StringVar()
        ttk.Entry(parent, textvariable=self.access_token_var, show="*").grid(
            row=6, column=0, sticky="ew", pady=(3, 6)
        )

        ttk.Label(
            parent,
            text="SOAP action (optional; inferred for SOAP requests)",
        ).grid(row=7, column=0, sticky="nw")
        self.action_var = tk.StringVar()
        ttk.Entry(parent, textvariable=self.action_var).grid(
            row=8, column=0, sticky="ew", pady=(3, 6)
        )

        body_header = ttk.Frame(parent)
        body_header.grid(row=9, column=0, sticky="ew")
        body_header.columnconfigure(0, weight=1)
        ttk.Label(body_header, text="Request body (XML or JSON)").grid(
            row=0, column=0, sticky="w"
        )
        ttk.Button(
            body_header,
            text="Load GetDeviceInformation example",
            command=self._load_device_information_example,
        ).grid(row=0, column=1, sticky="e")

        self.body_text = tk.Text(parent, height=8, wrap=tk.NONE, undo=True)
        self.body_text.grid(row=10, column=0, sticky="nsew", pady=(3, 8))
        self.body_text.insert(
            "1.0",
            '<tds:GetDeviceInformation xmlns:tds="'
            f'{DEVICE_NS}"/>',
        )
        body_scroll = ttk.Scrollbar(
            parent, orient=tk.VERTICAL, command=self.body_text.yview
        )
        body_scroll.grid(row=10, column=1, sticky="ns", pady=(3, 8))
        self.body_text.configure(yscrollcommand=body_scroll.set)

        request_bar = ttk.Frame(parent)
        request_bar.grid(row=11, column=0, sticky="nsew")
        request_bar.columnconfigure(0, weight=1)
        ttk.Label(request_bar, text="Response").grid(row=0, column=0, sticky="w")
        self.send_button = ttk.Button(
            request_bar, text="Send command", command=self._send_command
        )
        self.send_button.grid(row=0, column=1, sticky="e")
        self.response_text = tk.Text(request_bar, height=10, wrap=tk.NONE)
        self.response_text.grid(row=1, column=0, columnspan=2, sticky="nsew", pady=(3, 0))
        request_bar.rowconfigure(1, weight=1)
        response_scroll = ttk.Scrollbar(
            request_bar, orient=tk.VERTICAL, command=self.response_text.yview
        )
        response_scroll.grid(row=1, column=2, sticky="ns", pady=(3, 0))
        self.response_text.configure(yscrollcommand=response_scroll.set)

    def _refresh_devices(self, select_index: int | None = None) -> None:
        self.device_list.delete(0, tk.END)
        for device in self.devices:
            scheme = "https" if device.use_https else "http"
            self.device_list.insert(
                tk.END, f"{device.name}  ({scheme}://{device.host}:{device.port})"
            )
        if select_index is not None and 0 <= select_index < len(self.devices):
            self.device_list.selection_set(select_index)
            self.device_list.activate(select_index)
            self._device_selected()

    def _selected_device(self) -> Device | None:
        selection = self.device_list.curselection()
        return self.devices[selection[0]] if selection else None

    def _add_device(self) -> None:
        try:
            name = self.name_var.get().strip() or self.host_var.get().strip()
            host = self.host_var.get().strip()
            port = int(self.port_var.get())
            if not name:
                raise ValueError("Enter a device name or host.")
            if not 1 <= port <= 65535:
                raise ValueError("Port must be between 1 and 65535.")
            device = Device(
                name=name,
                host=host,
                port=port,
                username=self.username_var.get(),
                use_https=self.https_var.get(),
                password=self.password_var.get(),
            )
            device.device_service_url
        except ValueError as exc:
            messagebox.showerror("Invalid device", str(exc), parent=self.root)
            return

        self.devices.append(device)
        self._refresh_devices(len(self.devices) - 1)
        self._save_device_list()

    def _remove_device(self) -> None:
        selection = self.device_list.curselection()
        if not selection:
            return
        del self.devices[selection[0]]
        self._refresh_devices()
        self.endpoint_var.set("")
        self.services.clear()
        self._clear_service_tree()
        template = TEMPLATES_BY_LABEL.get(self.template_var.get())
        if template is not None and template.namespace:
            self._set_template_endpoint(template)
        self.username_var.set("")
        self.password_var.set("")
        self._save_device_list()

    def _save_device_list(self) -> None:
        try:
            save_devices(self.devices)
        except RuntimeError as exc:
            messagebox.showerror("Could not save devices", str(exc), parent=self.root)

    def _device_selected(self, _event: tk.Event | None = None) -> None:
        device = self._selected_device()
        if device is None:
            return
        self.name_var.set(device.name)
        self.host_var.set(device.host)
        self.port_var.set(str(device.port))
        self.username_var.set(device.username)
        self.password_var.set(device.password)
        self.https_var.set(device.use_https)
        try:
            self.endpoint_var.set(device.device_service_url)
        except ValueError:
            self.endpoint_var.set("")
        self.services.clear()
        self._clear_service_tree()

    def _update_device_endpoint(self) -> None:
        device = self._selected_device()
        if device is not None:
            device.use_https = self.https_var.get()
            try:
                self.endpoint_var.set(device.device_service_url)
            except ValueError:
                self.endpoint_var.set("")
            self._save_device_list()

    def _current_credentials(self) -> tuple[Device, str, str]:
        device = self._selected_device()
        if device is None:
            raise ValueError("Add or select a device first.")
        username = self.username_var.get()
        password = self.password_var.get()
        device.username = username
        device.password = password
        return device, username, password

    def _fetch_services(self) -> None:
        try:
            device, username, password = self._current_credentials()
            endpoint = device.device_service_url
        except ValueError as exc:
            messagebox.showerror("Cannot fetch services", str(exc), parent=self.root)
            return
        self._start_request(
            "Fetching ONVIF services…",
            lambda: get_services(endpoint, username, password),
            "services",
        )

    def _send_command(self) -> None:
        template = TEMPLATES_BY_LABEL.get(self.template_var.get())
        transport = template.transport if template is not None else "SOAP"
        body = self.body_text.get("1.0", "end-1c").strip()
        endpoint = self.endpoint_var.get().strip()
        access_token = self.access_token_var.get()
        action = ""

        try:
            if transport == "SOAP":
                _device, username, password = self._current_credentials()
                endpoint = validate_endpoint(endpoint)
                if not body:
                    raise ValueError("Enter one SOAP operation element in the request body.")
                action = self.action_var.get().strip() or infer_soap_action(body)
                operation = lambda: send_soap(
                    endpoint,
                    body,
                    username,
                    password,
                    soap_action=action,
                )
            elif transport == "WebSocket":
                endpoint = validate_websocket_endpoint(endpoint)
                if not body:
                    raise ValueError("Enter a JSON-RPC request in the request body.")
                operation = lambda: send_websocket_json_rpc(
                    endpoint,
                    body,
                    access_token,
                )
            elif transport == "HTTP GET":
                endpoint = validate_endpoint(endpoint)
                operation = lambda: send_http_get(endpoint, access_token)
            else:
                raise ValueError(f"Unsupported command transport: {transport}")
        except ValueError as exc:
            messagebox.showerror("Cannot send request", str(exc), parent=self.root)
            return
        if transport == "SOAP":
            self.action_var.set(action)
        self._start_request(
            f"Sending {transport} command to {endpoint}…",
            operation,
            transport,
        )

    def _start_request(
        self,
        status: str,
        operation: Callable[
            [], CommandResponse | tuple[CommandResponse, list[OnvifService]]
        ],
        result_kind: str,
    ) -> None:
        if self.busy:
            return
        self.busy = True
        self.status_var.set(status)
        self.fetch_button.configure(state=tk.DISABLED)
        self.send_button.configure(state=tk.DISABLED)

        def run() -> None:
            try:
                result = operation()
                self.results.put((result_kind, result, True))
            except (OSError, RuntimeError, ValueError) as exc:
                self.results.put((result_kind, exc, False))

        threading.Thread(target=run, daemon=True).start()

    def _poll_results(self) -> None:
        try:
            while True:
                result_kind, result, succeeded = self.results.get_nowait()
                self.busy = False
                self.fetch_button.configure(state=tk.NORMAL)
                self.send_button.configure(state=tk.NORMAL)
                if not succeeded:
                    self.status_var.set("Request failed")
                    messagebox.showerror(
                        "ONVIF request failed", str(result), parent=self.root
                    )
                    continue
                if isinstance(result, Exception):
                    self.status_var.set("Request failed")
                    messagebox.showerror(
                        "ONVIF request failed", str(result), parent=self.root
                    )
                    continue
                if result_kind == "services":
                    if not isinstance(result, tuple):
                        self.status_var.set("GetServices returned an invalid result")
                        continue
                    response, services = result
                    self.services = services
                    self._populate_services()
                    template = TEMPLATES_BY_LABEL.get(self.template_var.get())
                    if template is not None and template.namespace:
                        self._set_template_endpoint(template)
                    self.status_var.set(f"Found {len(services)} ONVIF services")
                    self._show_response(response, "SOAP")
                else:
                    if not isinstance(result, CommandResponse):
                        self.status_var.set("Command returned an invalid result")
                        continue
                    self._show_response(result, result_kind)
                    if result_kind == "WebSocket":
                        self.status_var.set("Received WebSocket JSON-RPC response")
                    else:
                        self.status_var.set(f"Received HTTP {result.status}")
        except queue.Empty:
            pass
        self.root.after(100, self._poll_results)

    def _populate_services(self) -> None:
        self._clear_service_tree()
        for index, service in enumerate(self.services):
            self.service_tree.insert(
                "",
                tk.END,
                iid=str(index),
                values=(service.namespace, service.xaddr, service.version),
            )

    def _clear_service_tree(self) -> None:
        for item in self.service_tree.get_children():
            self.service_tree.delete(item)

    def _use_selected_service(self, _event: tk.Event | None = None) -> None:
        selection = self.service_tree.selection()
        if selection:
            self.endpoint_var.set(self.services[int(selection[0])].xaddr)

    def _load_device_information_example(self) -> None:
        self.template_var.set("Custom SOAP")
        device = self._selected_device()
        if device is not None:
            self.endpoint_var.set(device.device_service_url)
        body = f'<tds:GetDeviceInformation xmlns:tds="{DEVICE_NS}"/>'
        self.body_text.delete("1.0", tk.END)
        self.body_text.insert("1.0", body)
        self.action_var.set(f"{DEVICE_NS}/GetDeviceInformation")

    def _template_selected(self, _event: tk.Event | None = None) -> None:
        template = TEMPLATES_BY_LABEL.get(self.template_var.get())
        if template is None:
            return
        self.body_text.delete("1.0", tk.END)
        self.body_text.insert("1.0", template.body)
        self.action_var.set(template.action)
        self._set_template_endpoint(template)
        description = template.description or f"{template.transport} command template."
        if template.namespace and not self.endpoint_var.get():
            description += (
                " No matching service endpoint is loaded. Fetch services or enter "
                "the endpoint manually."
            )
        self.status_var.set(description)

    def _set_template_endpoint(self, template: CommandTemplate) -> None:
        if template.endpoint:
            self.endpoint_var.set(template.endpoint)
        elif template.namespace:
            device = self._selected_device()
            endpoint = ""
            if template.namespace == DEVICE_NS and device is not None:
                endpoint = device.device_service_url
            else:
                service = next(
                    (
                        service
                        for service in self.services
                        if service.namespace == template.namespace
                    ),
                    None,
                )
                if service is not None:
                    endpoint = service.xaddr
            self.endpoint_var.set(endpoint)

    def _show_response(self, response: CommandResponse, transport: str) -> None:
        self.response_text.delete("1.0", tk.END)
        if transport == "SOAP":
            content = format_soap_response(response.body)
            header = f"HTTP {response.status}"
        elif transport == "HTTP GET":
            try:
                content = json.dumps(
                    json.loads(response.body), indent=2, ensure_ascii=False
                )
            except json.JSONDecodeError:
                content = response.body
            header = f"HTTP {response.status}"
        else:
            content = response.body
            header = "WebSocket JSON-RPC"
        self.response_text.insert("1.0", f"{header}\n\n{content}")


def main() -> None:
    root = tk.Tk()
    OnvifCommandStudio(root)
    root.mainloop()


if __name__ == "__main__":
    main()
