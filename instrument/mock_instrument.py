"""
Mock TSI Modbus TCP instrument.

Emulates enough of a TSI particle counter's Modbus TCP interface (see
tsi_modbus.py / TSIClient) to let the main app connect, read device info,
read records, read location labels, and send control commands (start/stop
measurement, clear data, purge, reboot, ...) against a fake instrument that
returns default/synthetic data instead of a real device.

Wire format quirks reproduced from TSIClient:
  - u16/u32/f32 fields are transmitted "byte swapped" (little-endian on the
    wire even though the protocol is nominally big-endian): TSIClient
    reverses the received bytes before interpreting them big-endian, so the
    server must send struct.pack("<...") for the intended big-endian value.
  - ASCII strings (model, serial, location/recipe labels) are transmitted
    with each adjacent byte pair swapped; TSIClient swaps them back before
    decoding.
  - Register writes (FC6) are plain/standard Modbus (no swapping).

Run standalone:
    python -m instrument.mock_instrument --port 5020
    python -m instrument.mock_instrument --count 3 --base-port 5020

Then point the main app at it, e.g.:
    curl -X POST http://localhost:8000/connect \
      -H "Content-Type: application/json" \
      -d '{"ip": "127.0.0.1", "port": 5020, "max_records": 20}'
"""

import argparse
import logging
import socket
import socketserver
import struct
import threading
from datetime import datetime, timedelta
from typing import Optional

log = logging.getLogger("mock_instrument")

# ─── Command codes (mirror TSIClient.CMD_*) ──────────────────────────────────

CMD_CLEAR_DATA = 1
CMD_START_PUMP = 2
CMD_MANUAL_START = 3
CMD_MANUAL_STOP = 4
CMD_STOP_PUMP = 5
CMD_AUTO_START = 6
CMD_AUTO_STOP = 7
CMD_SET_RTC = 8
CMD_DISABLE_LOCAL_CTL = 12
CMD_ENABLE_LOCAL_CTL = 13
CMD_SILENCE_DEVICE = 14
CMD_UNSILENCE_DEVICE = 15
CMD_REBOOT_UNIT = 29
CMD_PURGE_START = 30

STATE_STOPPED = 0
STATE_START_DELAY = 1
STATE_SAMPLING = 2
STATE_MANUAL_SAMPLING = 3
STATE_PURGING = 4


def _binary_address(reg_1based: int) -> int:
    return reg_1based - 40001


# ─── Wire-format helpers (match TSIClient's swap logic) ──────────────────────

def _wire_u16(v: int) -> bytes:
    return struct.pack("<H", v & 0xFFFF)


def _wire_u32(v: int) -> bytes:
    return struct.pack("<I", v & 0xFFFFFFFF)


def _wire_f32(v: float) -> bytes:
    return struct.pack("<f", v)


def _pair_swap(data: bytes) -> bytes:
    b = bytearray(data)
    for i in range(0, len(b) - 1, 2):
        b[i], b[i + 1] = b[i + 1], b[i]
    return bytes(b)


def _wire_str(s: str, length: int) -> bytes:
    raw = s.encode("ascii", errors="ignore")[:length].ljust(length, b"\x00")
    return _pair_swap(raw)


def _put(buf: bytearray, offset: int, data: bytes):
    end = offset + len(data)
    if offset < 0 or end > len(buf):
        return
    buf[offset:end] = data


# ─── The mock instrument ─────────────────────────────────────────────────────

class MockInstrument:
    """Holds the fake device state and answers Modbus read/write requests."""

    def __init__(
        self,
        model: str = "TSI 9306",
        serial: str = "MOCK0001",
        firmware_version: int = 210,
        num_channels: int = 6,
        channel_sizes=None,
        flow_unit: str = "CFM",
        nominal_flow: float = 1.00,
        num_locations: int = 5,
        num_recipes: int = 5,
        num_records: int = 10,
    ):
        self.model = model
        self.serial = serial
        self.firmware_version = firmware_version
        self.num_channels = num_channels
        self.channel_sizes = channel_sizes or [300, 500, 1000, 3000, 5000, 10000, 0, 0,
                                                0, 0, 0, 0, 0, 0, 0, 0]
        self.flow_unit = flow_unit
        self.nominal_flow = nominal_flow
        self.flow_rate = nominal_flow
        self.sample_time_sec = 60
        self.num_locations = num_locations
        self.num_recipes = num_recipes
        self.viable_counts = False
        self.has_data_integrity = False
        self.last_calibration_date = datetime(2025, 1, 15)
        self.calibration_due_date = datetime(2026, 1, 15)

        self.locations = {i: f"Location {i}" for i in range(1, num_locations + 1)}
        self.recipes = {i: f"Recipe {i}" for i in range(1, num_recipes + 1)}

        self.num_records = num_records
        self.base_time = datetime.now() - timedelta(minutes=num_records)

        self.status_raw = 0  # state (high byte) + alarm bits (low byte)
        self.pump_on = False
        self.local_control_enabled = True
        self.silenced = False

        self._record_index_hi = 0
        self._record_index_lo = 0
        self._selected_location = 1
        self._selected_recipe = 1
        self._rtc = {}

        self._lock = threading.Lock()

    # ── FC3: Read Holding Registers ──────────────────────────────────────────

    def read_registers(self, start: int, count: int) -> bytes:
        with self._lock:
            if start == _binary_address(40003):  # model
                return self._model_bytes()[: count * 2].ljust(count * 2, b"\x00")
            if start == _binary_address(40011):  # serial
                return self._serial_bytes()[: count * 2].ljust(count * 2, b"\x00")
            if start == _binary_address(41002):  # status
                return _wire_u16(self.status_raw)
            if start == _binary_address(41003):  # device info
                return self._device_info_bytes()[: count * 2].ljust(count * 2, b"\x00")
            if start == _binary_address(42001):  # num samples (uint32)
                return _wire_u32(self.num_records).ljust(count * 2, b"\x00")
            if start == _binary_address(42005):  # record payload
                return self._record_bytes(count)
            if start == _binary_address(43001):  # location label
                return self._location_bytes()[: count * 2].ljust(count * 2, b"\x00")
            if start == _binary_address(43018):  # recipe label
                return self._recipe_bytes()[: count * 2].ljust(count * 2, b"\x00")
            return b"\x00" * (count * 2)

    def _model_bytes(self) -> bytes:
        return _wire_str(self.model, 16)

    def _serial_bytes(self) -> bytes:
        return _wire_str(self.serial, 16)

    def _device_info_bytes(self) -> bytes:
        parts = [
            _wire_u16(self.firmware_version),
            _wire_str(self.model, 16),
            _wire_str(self.serial, 16),
            b"\x00" * 16,  # algorithm id (unused)
            _wire_u16(self.last_calibration_date.year)
            + _wire_u16(self.last_calibration_date.month)
            + _wire_u16(self.last_calibration_date.day),
            _wire_u16(self.calibration_due_date.year)
            + _wire_u16(self.calibration_due_date.month)
            + _wire_u16(self.calibration_due_date.day),
        ]
        flow_raw = int(round(self.nominal_flow * 100)) & 0x7FFF
        flow_raw |= 0x8000 if self.flow_unit == "LPM" else 0
        parts.append(_wire_u16(flow_raw))
        parts.append(_wire_u16(self.num_channels))
        parts.append(_wire_u16(0))  # device features
        sizes = (self.channel_sizes + [0] * 16)[:16]
        for sz in sizes:
            parts.append(_wire_u16(sz))
        dev_feat2 = (1 if self.viable_counts else 0) | (16 if self.has_data_integrity else 0)
        parts.append(_wire_u16(dev_feat2))
        parts.append(b"\x00" * 16)  # reserved
        parts.append(_wire_u16(0))  # supported measurements
        parts.append(b"\x00" * 6)
        parts.append(_wire_u16(self.num_locations))
        parts.append(b"\x00" * 2)
        parts.append(_wire_u16(self.num_recipes))
        return b"".join(parts)

    def _record_bytes(self, count: int) -> bytes:
        byte_count = count * 2
        buf = bytearray(byte_count)
        rec_index = (self._record_index_hi << 16) | self._record_index_lo
        rec_index = max(0, min(rec_index, max(self.num_records - 1, 0)))

        ts = self.base_time + timedelta(minutes=rec_index)
        _put(buf, 0, _wire_u32(rec_index + 1))
        _put(buf, 4, _wire_u16(ts.year))
        _put(buf, 6, _wire_u16(ts.month))
        _put(buf, 8, _wire_u16(ts.day))
        _put(buf, 10, _wire_u16(ts.hour))
        _put(buf, 12, _wire_u16(ts.minute))
        _put(buf, 14, _wire_u16(ts.second))
        _put(buf, 20, _wire_u16(0))                       # viable detection sensitivity
        _put(buf, 22, _wire_f32(self.flow_rate))          # precision flow rate
        _put(buf, 26, _wire_u16(0))                       # device status
        _put(buf, 28, _wire_u16(0))                       # channel alarm mask

        flow_x100 = int(round(self.flow_rate * 100)) & 0x7FFF
        flow_raw = flow_x100 | (0x8000 if self.flow_unit == "LPM" else 0)
        _put(buf, 30, _wire_u16(flow_raw))
        _put(buf, 32, _wire_u32(self.sample_time_sec))    # sample time (seconds)
        _put(buf, 36, _wire_u16(1))                       # time unit: 1 = seconds
        _put(buf, 38, _wire_u16(0))                       # differential + counts
        loc_ids = list(self.locations.keys()) or [0]
        _put(buf, 40, _wire_u16(loc_ids[rec_index % len(loc_ids)]))

        for i in range(16):
            value = (rec_index + 1) * (i + 1) * 3 if i < self.num_channels else 0
            _put(buf, 42 + i * 4, _wire_u32(value))
        for i in range(16):
            size = self.channel_sizes[i] if i < len(self.channel_sizes) else 0
            _put(buf, 106 + i * 2, _wire_u16(size))

        if byte_count >= 2:
            _put(buf, byte_count - 2, _wire_u16(0))       # measurementEnabled = none

        return bytes(buf)

    def _location_bytes(self) -> bytes:
        name = self.locations.get(self._selected_location, "")
        raw = struct.pack(">H", self._selected_location) + name.encode(
            "ascii", errors="ignore"
        ).ljust(32, b"\x00")[:32]
        return _pair_swap(raw)

    def _recipe_bytes(self) -> bytes:
        name = self.recipes.get(self._selected_recipe, "")
        raw = struct.pack(">H", self._selected_recipe) + name.encode(
            "ascii", errors="ignore"
        ).ljust(32, b"\x00")[:32]
        return _pair_swap(raw)

    # ── FC6: Write Single Register ───────────────────────────────────────────

    def write_register(self, reg: int, value: int):
        with self._lock:
            if reg == _binary_address(41001):
                self._handle_command(value)
            elif reg == _binary_address(41078):
                self._record_index_hi = value
            elif reg == _binary_address(41079):
                self._record_index_lo = value
            elif _binary_address(41006) <= reg <= _binary_address(41011):
                offset = reg - _binary_address(41006)
                self._rtc[["year", "month", "day", "hour", "minute", "second"][offset]] = value
            elif reg == _binary_address(43001):
                self._selected_location = value
            elif reg == _binary_address(43018):
                self._selected_recipe = value

    def _handle_command(self, code: int):
        log.info(f"[{self.serial}] command received: {code}")
        if code == CMD_CLEAR_DATA:
            self.num_records = 0
            self.base_time = datetime.now()
        elif code == CMD_START_PUMP:
            self.pump_on = True
        elif code == CMD_STOP_PUMP:
            self.pump_on = False
        elif code == CMD_MANUAL_START:
            self.status_raw = STATE_MANUAL_SAMPLING << 8
        elif code == CMD_MANUAL_STOP:
            self.status_raw = STATE_STOPPED << 8
            self.num_records += 1
        elif code == CMD_AUTO_START:
            self.status_raw = STATE_SAMPLING << 8
        elif code == CMD_AUTO_STOP:
            self.status_raw = STATE_STOPPED << 8
        elif code == CMD_SET_RTC:
            pass  # RTC fields already stored via write_register
        elif code == CMD_DISABLE_LOCAL_CTL:
            self.local_control_enabled = False
        elif code == CMD_ENABLE_LOCAL_CTL:
            self.local_control_enabled = True
        elif code == CMD_SILENCE_DEVICE:
            self.silenced = True
        elif code == CMD_UNSILENCE_DEVICE:
            self.silenced = False
        elif code == CMD_PURGE_START:
            self.status_raw = STATE_PURGING << 8
        elif code == CMD_REBOOT_UNIT:
            self.status_raw = STATE_STOPPED << 8
            self.pump_on = False


# ─── Modbus TCP server plumbing ───────────────────────────────────────────────

def _recv_exact(sock: socket.socket, n: int) -> Optional[bytes]:
    data = bytearray()
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            return None
        data.extend(chunk)
    return bytes(data)


class _ModbusHandler(socketserver.BaseRequestHandler):
    def handle(self):
        sock: socket.socket = self.request
        sock.settimeout(60)
        instrument: MockInstrument = self.server.instrument  # type: ignore[attr-defined]
        while True:
            try:
                header = _recv_exact(sock, 7)
                if not header:
                    break
                tid, _proto, length, unit = struct.unpack(">HHHB", header)
                pdu = _recv_exact(sock, length - 1)
                if pdu is None:
                    break
                resp = self._handle_pdu(instrument, pdu)
                if resp is None:
                    continue
                mbap = struct.pack(">HHHB", tid, 0, len(resp) + 1, unit)
                sock.sendall(mbap + resp)
            except (socket.timeout, ConnectionResetError, OSError):
                break

    def _handle_pdu(self, instrument: MockInstrument, pdu: bytes) -> Optional[bytes]:
        func = pdu[0]
        if func == 3:  # Read Holding Registers
            start, count = struct.unpack(">HH", pdu[1:5])
            data = instrument.read_registers(start, count)
            return bytes([3, len(data)]) + data
        if func == 6:  # Write Single Register
            reg, value = struct.unpack(">HH", pdu[1:5])
            instrument.write_register(reg, value)
            return bytes([6]) + pdu[1:5]
        log.warning(f"Unsupported function code {func}, ignoring")
        return None


class MockInstrumentServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, host: str, port: int, instrument: MockInstrument):
        super().__init__((host, port), _ModbusHandler)
        self.instrument = instrument


def run_server(host: str, port: int, instrument: Optional[MockInstrument] = None) -> MockInstrumentServer:
    """Start a mock instrument server in a background thread and return it."""
    server = MockInstrumentServer(host, port, instrument or MockInstrument())
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    log.info(f"Mock TSI instrument '{server.instrument.serial}' listening on {host}:{port}")
    return server


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    parser = argparse.ArgumentParser(description="Run one or more mock TSI Modbus TCP instruments")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5020, help="Port for a single instrument")
    parser.add_argument("--base-port", type=int, default=None,
                         help="First port when launching multiple instruments (--count > 1)")
    parser.add_argument("--count", type=int, default=1, help="Number of mock instruments to launch")
    parser.add_argument("--records", type=int, default=10, help="Number of default records per instrument")
    args = parser.parse_args()

    base_port = args.base_port if args.base_port is not None else args.port
    servers = []
    for i in range(args.count):
        instrument = MockInstrument(
            model="TSI 9306",
            serial=f"MOCK{i + 1:04d}",
            num_records=args.records,
        )
        servers.append(run_server(args.host, base_port + i, instrument))

    print(f"{len(servers)} mock instrument(s) running. Press Ctrl+C to stop.")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        print("Shutting down...")
        for s in servers:
            s.shutdown()


if __name__ == "__main__":
    main()
