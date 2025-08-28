from __future__ import annotations

import concurrent.futures
import logging
import sys
import tkinter as tk
from tkinter import messagebox, ttk
from typing import Callable, Iterable, List, Optional, Sequence, Tuple

from .modbus_client import ModbusTcpClient


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
LOGGER = logging.getLogger("modbus_ui")


class LabeledEntry(ttk.Frame):
    def __init__(self, master: tk.Misc, label: str, width: int = 16) -> None:
        super().__init__(master)
        self.var = tk.StringVar()
        self.label_widget = ttk.Label(self, text=label)
        self.entry_widget = ttk.Entry(self, textvariable=self.var, width=width)
        self.label_widget.grid(row=0, column=0, sticky="w", padx=(0, 6))
        self.entry_widget.grid(row=0, column=1, sticky="ew")
        self.columnconfigure(1, weight=1)

    def get_str(self) -> str:
        return self.var.get().strip()

    def set_str(self, value: str) -> None:
        self.var.set(value)


class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Modbus TCP Master")
        self.geometry("860x520")

        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=2)
        self.client: Optional[ModbusTcpClient] = None

        self._build_ui()

    # ---- UI construction ----------------------------------------------
    def _build_ui(self) -> None:
        root = self
        padding = {"padx": 8, "pady": 6}

        # Connection frame
        conn_frame = ttk.LabelFrame(root, text="Connection")
        conn_frame.pack(fill="x", padx=10, pady=10)

        self.host_entry = LabeledEntry(conn_frame, "Host")
        self.port_entry = LabeledEntry(conn_frame, "Port")
        self.unit_entry = LabeledEntry(conn_frame, "Unit ID")
        self.timeout_entry = LabeledEntry(conn_frame, "Timeout (s)")

        self.host_entry.set_str("127.0.0.1")
        self.port_entry.set_str("502")
        self.unit_entry.set_str("1")
        self.timeout_entry.set_str("2.0")

        self.host_entry.grid(row=0, column=0, **padding)
        self.port_entry.grid(row=0, column=1, **padding)
        self.unit_entry.grid(row=0, column=2, **padding)
        self.timeout_entry.grid(row=0, column=3, **padding)

        self.connect_btn = ttk.Button(conn_frame, text="Connect", command=self.on_connect_clicked)
        self.disconnect_btn = ttk.Button(conn_frame, text="Disconnect", command=self.on_disconnect_clicked, state=tk.DISABLED)
        self.status_label = ttk.Label(conn_frame, text="Disconnected", foreground="red")

        self.connect_btn.grid(row=0, column=4, **padding)
        self.disconnect_btn.grid(row=0, column=5, **padding)
        self.status_label.grid(row=0, column=6, sticky="w", **padding)

        # Tabs for read/write
        notebook = ttk.Notebook(root)
        notebook.pack(fill="both", expand=True, padx=10, pady=10)

        self.read_tab = ttk.Frame(notebook)
        self.write_tab = ttk.Frame(notebook)
        notebook.add(self.read_tab, text="Read")
        notebook.add(self.write_tab, text="Write")

        self._build_read_tab(self.read_tab)
        self._build_write_tab(self.write_tab)

    def _build_read_tab(self, parent: tk.Misc) -> None:
        padding = {"padx": 8, "pady": 6}

        opts_frame = ttk.LabelFrame(parent, text="Read Options")
        opts_frame.pack(fill="x", padx=6, pady=6)

        self.read_func_var = tk.StringVar(value="Holding Registers")
        ttk.Label(opts_frame, text="Function").grid(row=0, column=0, sticky="w", **padding)
        self.read_func = ttk.Combobox(
            opts_frame,
            textvariable=self.read_func_var,
            values=[
                "Coils",
                "Discrete Inputs",
                "Holding Registers",
                "Input Registers",
            ],
            state="readonly",
            width=22,
        )
        self.read_func.grid(row=0, column=1, **padding)

        self.read_addr = LabeledEntry(opts_frame, "Address")
        self.read_qty = LabeledEntry(opts_frame, "Quantity")
        self.read_addr.set_str("0")
        self.read_qty.set_str("1")
        self.read_addr.grid(row=0, column=2, **padding)
        self.read_qty.grid(row=0, column=3, **padding)

        self.read_btn = ttk.Button(opts_frame, text="Read", command=self.on_read_clicked, state=tk.DISABLED)
        self.read_btn.grid(row=0, column=4, **padding)

        result_frame = ttk.LabelFrame(parent, text="Result")
        result_frame.pack(fill="both", expand=True, padx=6, pady=6)
        self.read_output = tk.Text(result_frame, height=14)
        self.read_output.pack(fill="both", expand=True, padx=8, pady=8)

    def _build_write_tab(self, parent: tk.Misc) -> None:
        padding = {"padx": 8, "pady": 6}

        opts_frame = ttk.LabelFrame(parent, text="Write Options")
        opts_frame.pack(fill="x", padx=6, pady=6)

        self.write_func_var = tk.StringVar(value="Single Register")
        ttk.Label(opts_frame, text="Operation").grid(row=0, column=0, sticky="w", **padding)
        self.write_func = ttk.Combobox(
            opts_frame,
            textvariable=self.write_func_var,
            values=[
                "Single Coil",
                "Single Register",
                "Multiple Registers",
            ],
            state="readonly",
            width=22,
        )
        self.write_func.grid(row=0, column=1, **padding)

        self.write_addr = LabeledEntry(opts_frame, "Address")
        self.write_values = LabeledEntry(opts_frame, "Value(s)")
        self.write_addr.set_str("0")
        self.write_values.set_str("1")
        self.write_addr.grid(row=0, column=2, **padding)
        self.write_values.grid(row=0, column=3, **padding)

        self.write_btn = ttk.Button(opts_frame, text="Write", command=self.on_write_clicked, state=tk.DISABLED)
        self.write_btn.grid(row=0, column=4, **padding)

        result_frame = ttk.LabelFrame(parent, text="Result")
        result_frame.pack(fill="both", expand=True, padx=6, pady=6)
        self.write_output = tk.Text(result_frame, height=14)
        self.write_output.pack(fill="both", expand=True, padx=8, pady=8)

    # ---- event handlers -------------------------------------------------
    def on_connect_clicked(self) -> None:
        try:
            host = self.host_entry.get_str()
            port = int(self.port_entry.get_str())
            unit_id = int(self.unit_entry.get_str())
            timeout_s = float(self.timeout_entry.get_str())
        except ValueError:
            messagebox.showerror("Invalid input", "Host, port, unit id, and timeout must be valid values.")
            return

        self.client = ModbusTcpClient(host=host, port=port, timeout_s=timeout_s, unit_id=unit_id)
        self._set_busy(True)
        self.status_label.config(text="Connecting...", foreground="orange")

        def do_connect() -> str:
            assert self.client is not None
            self.client.connect()
            return "Connected"

        future = self.executor.submit(do_connect)
        future.add_done_callback(lambda f: self.after(0, self._after_connect, f))

    def _after_connect(self, future: concurrent.futures.Future) -> None:
        self._set_busy(False)
        try:
            _ = future.result()
        except Exception as exc:  # noqa: BLE001
            LOGGER.exception("Connect failed: %s", exc)
            self.status_label.config(text=f"Connect failed: {exc}", foreground="red")
            self.client = None
            return

        self.status_label.config(text="Connected", foreground="green")
        self.connect_btn.config(state=tk.DISABLED)
        self.disconnect_btn.config(state=tk.NORMAL)
        self.read_btn.config(state=tk.NORMAL)
        self.write_btn.config(state=tk.NORMAL)

    def on_disconnect_clicked(self) -> None:
        if self.client is None:
            return
        self._set_busy(True)
        self.status_label.config(text="Disconnecting...", foreground="orange")

        client = self.client

        def do_disconnect() -> str:
            client.disconnect()
            return "Disconnected"

        future = self.executor.submit(do_disconnect)
        future.add_done_callback(lambda f: self.after(0, self._after_disconnect, f))

    def _after_disconnect(self, future: concurrent.futures.Future) -> None:
        self._set_busy(False)
        try:
            _ = future.result()
        except Exception as exc:  # noqa: BLE001
            LOGGER.warning("Disconnect error: %s", exc)
        finally:
            self.client = None
            self.status_label.config(text="Disconnected", foreground="red")
            self.connect_btn.config(state=tk.NORMAL)
            self.disconnect_btn.config(state=tk.DISABLED)
            self.read_btn.config(state=tk.DISABLED)
            self.write_btn.config(state=tk.DISABLED)

    def on_read_clicked(self) -> None:
        if self.client is None:
            messagebox.showerror("Not connected", "Please connect first.")
            return
        try:
            address = int(self.read_addr.get_str())
            quantity = int(self.read_qty.get_str())
            if quantity <= 0:
                raise ValueError
        except ValueError:
            messagebox.showerror("Invalid input", "Address must be int, quantity must be positive int.")
            return

        func = self.read_func_var.get()
        self.read_output.delete("1.0", tk.END)
        self.read_output.insert(tk.END, f"Reading {func} at {address}, qty={quantity}...\n")

        def do_read() -> Tuple[int, ...]:
            assert self.client is not None
            if func == "Coils":
                return self.client.read_coils(address, quantity)
            if func == "Discrete Inputs":
                return self.client.read_discrete_inputs(address, quantity)
            if func == "Holding Registers":
                return self.client.read_holding_registers(address, quantity)
            if func == "Input Registers":
                return self.client.read_input_registers(address, quantity)
            raise RuntimeError(f"Unsupported function: {func}")

        future = self.executor.submit(do_read)
        future.add_done_callback(lambda f: self.after(0, self._after_read, f))

    def _after_read(self, future: concurrent.futures.Future) -> None:
        try:
            result = future.result()
        except Exception as exc:  # noqa: BLE001
            LOGGER.exception("Read failed: %s", exc)
            self.read_output.insert(tk.END, f"Error: {exc}\n")
            return

        self.read_output.insert(tk.END, f"Result: {list(result)}\n")

    def on_write_clicked(self) -> None:
        if self.client is None:
            messagebox.showerror("Not connected", "Please connect first.")
            return
        try:
            address = int(self.write_addr.get_str())
        except ValueError:
            messagebox.showerror("Invalid input", "Address must be an integer.")
            return

        op = self.write_func_var.get()
        values_text = self.write_values.get_str()

        self.write_output.delete("1.0", tk.END)
        self.write_output.insert(tk.END, f"Writing {op} at {address} with '{values_text}'...\n")

        try:
            if op == "Single Coil":
                val = values_text.strip()
                if val.lower() in {"true", "on", "1"}:
                    parsed: List[int] = [1]
                elif val.lower() in {"false", "off", "0"}:
                    parsed = [0]
                else:
                    parsed = [int(val)]
            elif op == "Single Register":
                parsed = [int(values_text)]
            elif op == "Multiple Registers":
                parts = [p for p in values_text.split(",") if p.strip()]
                parsed = [int(p.strip()) for p in parts]
                if not parsed:
                    raise ValueError
            else:
                raise RuntimeError(f"Unsupported op: {op}")
        except ValueError:
            messagebox.showerror("Invalid input", "Value(s) must be integer(s). For multiple, use comma-separated list.")
            return

        def do_write() -> Tuple[int, ...]:
            assert self.client is not None
            if op == "Single Coil":
                return self.client.write_single_coil(address, parsed[0])
            if op == "Single Register":
                return self.client.write_single_register(address, parsed[0])
            if op == "Multiple Registers":
                return self.client.write_multiple_registers(address, parsed)
            raise RuntimeError(f"Unsupported op: {op}")

        future = self.executor.submit(do_write)
        future.add_done_callback(lambda f: self.after(0, self._after_write, f))

    def _after_write(self, future: concurrent.futures.Future) -> None:
        try:
            result = future.result()
        except Exception as exc:  # noqa: BLE001
            LOGGER.exception("Write failed: %s", exc)
            self.write_output.insert(tk.END, f"Error: {exc}\n")
            return
        self.write_output.insert(tk.END, f"Result: {list(result)}\n")

    # ---- helpers --------------------------------------------------------
    def _set_busy(self, busy: bool) -> None:
        widgets: List[tk.Widget] = [
            self.connect_btn,
            self.disconnect_btn,
            self.read_btn,
            self.write_btn,
        ]
        for w in widgets:
            try:
                w.config(state=tk.DISABLED if busy else tk.NORMAL)
            except tk.TclError:
                pass


def main() -> None:
    try:
        app = App()
        app.mainloop()
    except tk.TclError as exc:
        LOGGER.error("Tkinter failed to start. Ensure Tk is installed. Error: %s", exc)
        sys.exit(1)


if __name__ == "__main__":
    main()

