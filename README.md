## Modbus TCP Master with Tkinter UI (Python 3.12)

This project provides a simple Modbus TCP master built on top of `modbus-tk` with a desktop user interface using `tkinter`/`ttk`. It supports connect/disconnect, reading coils/inputs/registers, and writing coils/registers (single and multiple).

### Requirements

- Python 3.12
- `modbus-tk` (installed via `requirements.txt`)
- On Linux, ensure the Tk GUI toolkit is available for Python. If `tkinter` is missing, install your distribution's Python Tk package (e.g., `sudo apt-get install python3-tk`).

### Setup

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
```

### Run

```bash
python -m src.app
```

### Features

- Connect/disconnect to a Modbus TCP server
- Read: Coils, Discrete Inputs, Holding Registers, Input Registers
- Write: Single Coil, Single Register, Multiple Registers
- Input validation and exception handling
- Non-blocking UI using a thread pool

### Notes

- For writing multiple registers, provide a comma-separated list of integers (e.g., `10,11,12`).
- Timeouts and ports are validated; error messages appear in the UI.
- Logging outputs to the console.

# cursor
cursor testing ground
