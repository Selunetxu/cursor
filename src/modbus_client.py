from __future__ import annotations

import logging
from typing import Iterable, List, Optional, Sequence, Tuple, Union

from modbus_tk import defines as cst
from modbus_tk import modbus_tcp


LOGGER = logging.getLogger(__name__)


class ModbusTcpClient:
    """Wrapper around modbus-tk TcpMaster providing typed helpers and safety.

    This class intentionally keeps a minimal surface area while providing clear
    methods for common read and write operations. It does not manage retries; the
    caller should perform any higher-level retry logic if needed.
    """

    def __init__(
        self,
        host: str,
        port: int = 502,
        timeout_s: float = 2.0,
        unit_id: int = 1,
    ) -> None:
        self.host: str = host
        self.port: int = port
        self.timeout_s: float = timeout_s
        self.unit_id: int = unit_id
        self._master: Optional[modbus_tcp.TcpMaster] = None

    # ---- lifecycle -----------------------------------------------------
    def connect(self) -> None:
        if self._master is not None:
            return
        LOGGER.info("Connecting to %s:%s (timeout=%ss, unit=%s)", self.host, self.port, self.timeout_s, self.unit_id)
        master = modbus_tcp.TcpMaster(host=self.host, port=self.port, timeout_in_sec=self.timeout_s)
        # Trigger a light ping: not strictly necessary, but verifies socket
        master.set_timeout(self.timeout_s)
        self._master = master

    def disconnect(self) -> None:
        if self._master is not None:
            try:
                self._master.close()
            except Exception as exc:  # noqa: BLE001 - ensure cleanup
                LOGGER.warning("Error during disconnect: %s", exc)
            finally:
                self._master = None

    @property
    def is_connected(self) -> bool:
        return self._master is not None

    # ---- read operations -----------------------------------------------
    def read_coils(self, address: int, quantity: int) -> Tuple[int, ...]:
        master = self._require_master()
        return master.execute(self.unit_id, cst.READ_COILS, address, quantity)

    def read_discrete_inputs(self, address: int, quantity: int) -> Tuple[int, ...]:
        master = self._require_master()
        return master.execute(self.unit_id, cst.READ_DISCRETE_INPUTS, address, quantity)

    def read_holding_registers(self, address: int, quantity: int) -> Tuple[int, ...]:
        master = self._require_master()
        return master.execute(self.unit_id, cst.READ_HOLDING_REGISTERS, address, quantity)

    def read_input_registers(self, address: int, quantity: int) -> Tuple[int, ...]:
        master = self._require_master()
        return master.execute(self.unit_id, cst.READ_INPUT_REGISTERS, address, quantity)

    # ---- write operations ----------------------------------------------
    def write_single_coil(self, address: int, value: Union[int, bool]) -> Tuple[int, ...]:
        master = self._require_master()
        int_value = 1 if bool(value) else 0
        return master.execute(self.unit_id, cst.WRITE_SINGLE_COIL, address, output_value=int_value)

    def write_single_register(self, address: int, value: int) -> Tuple[int, ...]:
        master = self._require_master()
        return master.execute(self.unit_id, cst.WRITE_SINGLE_REGISTER, address, output_value=int(value))

    def write_multiple_registers(self, address: int, values: Sequence[int]) -> Tuple[int, ...]:
        master = self._require_master()
        payload: List[int] = [int(v) for v in values]
        return master.execute(self.unit_id, cst.WRITE_MULTIPLE_REGISTERS, address, output_value=payload)

    # ---- helpers --------------------------------------------------------
    def _require_master(self) -> modbus_tcp.TcpMaster:
        if self._master is None:
            raise RuntimeError("Not connected. Call connect() first.")
        return self._master

