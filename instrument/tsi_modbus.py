"""
TSI Modbus TCP Client
Port del protocollo C# TrakProLite → Python puro (struct + socket).

Registri Modbus (indirizzi 1-based dal C#, convertiti in 0-based con BinaryAddress = reg - 40001 o reg - 41001):
  40003..40010  → model (8 reg × 2 byte = 16 char)
  40011..40018  → serial (8 reg)
  41078..41079  → indice record (hi/lo 32-bit)
  42001..42002  → numero campioni (uint32)
  42005..42122  → record dati (~118 reg)
  43001..43017  → location label (17 reg)
  43018..43034  → recipe  label (17 reg)
  device info   → 42200+ (leggi ReadDeviceInfo)

Il blocco record letto da 42005 ha questa struttura (vedi ModbusInterpreter.InterpretRecord):
  offset 0  : uint32  recNum
  offset 4  : uint16  year
  offset 6  : uint16  month
  offset 8  : uint16  day
  offset 10 : uint16  hour
  offset 12 : uint16  minute
  offset 14 : uint16  second
  offset 16 : uint16  (padding/skip 4 bytes)
  offset 20 : uint16  ViableDetectionSensitivity
  offset 22 : uint32  PrecisionFlowRate (float)
  offset 26 : uint16  DeviceStatus
  offset 28 : uint16  chAlarm bitmask
  offset 30 : uint16  flowRateX100 + flowType bit15
  offset 32 : uint32  sampleTime value
  offset 36 : uint16  timeUnit (0=ms,1=sec)
  offset 38 : uint16  countMode / unitMode
  offset 40 : uint16  locNumber
  offset 42 : uint32×16  counts[0..15]  (64 bytes)
  offset 106: uint16×16  chSizes[0..15] (32 bytes)
  offset 138: ... misure ambientali (temp, humidity, vel, flow, CO2, CO, pressure)
"""

import socket
import struct
import random
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

# ─── Registro comandi (vedi TSIModbusRegisterMap.cs) ─────────────────────────
# Tutti i comandi di controllo vengono scritti nel registro 41001.

log = logging.getLogger("tsi_modbus")

PORT = 502
TIMEOUT = 3.0


# ─── helpers Modbus TCP ───────────────────────────────────────────────────────

def _transaction_id() -> int:
    return random.randint(0, 0xFFFF)


def _modbus_read(unit: int, start_reg: int, count: int) -> bytes:
    """Crea pacchetto Modbus TCP FC3 (Read Holding Registers)."""
    if count > 125:
        raise ValueError("count > 125 non supportato")
    tid = _transaction_id()
    return struct.pack(">HHHBBHH", tid, 0, 6, unit, 3, start_reg, count)


def _modbus_write_single(unit: int, reg: int, value: int) -> bytes:
    """Crea pacchetto Modbus TCP FC6 (Write Single Register)."""
    tid = _transaction_id()
    return struct.pack(">HHHBBHH", tid, 0, 6, unit, 6, reg, value)


def _binary_address(reg_1based: int) -> int:
    """Converte indirizzo 1-based (es. 42005) in 0-based per Modbus: reg - 40001."""
    return reg_1based - 40001


def _swap_bytes(data: bytes, offset: int, length: int) -> bytearray:
    """Array.Reverse su coppie di byte (swap big/little endian per segmento)."""
    arr = bytearray(data)
    for i in range(offset, offset + length, 2):
        if i + 1 < len(arr):
            arr[i], arr[i + 1] = arr[i + 1], arr[i]
    return arr


def _swap_and_read_u16(data: bytearray, offset: int) -> int:
    b = bytearray(data[offset:offset + 2])
    b.reverse()
    return struct.unpack_from(">H", b)[0]


def _swap_and_read_u32(data: bytearray, offset: int) -> int:
    b = bytearray(data[offset:offset + 4])
    b.reverse()
    return struct.unpack_from(">I", b)[0]


def _swap_and_read_f32(data: bytearray, offset: int) -> float:
    b = bytearray(data[offset:offset + 4])
    b.reverse()
    return struct.unpack_from(">f", b)[0]


# ─── Classi dati ─────────────────────────────────────────────────────────────

@dataclass
class TSIChannel:
    size_um: float          # dimensione particella in µm
    count: int              # conteggio particelle
    alarm: bool = False


@dataclass
class TSIRecord:
    rec_num: int
    timestamp: datetime
    location_id: int
    location_name: str = ""
    flow_rate: float = 0.0          # LPM o CFM
    flow_type: str = "CFM"          # "LPM" | "CFM"
    sample_time_sec: int = 0
    count_mode: str = "Differential"  # "Differential" | "Cumulative"
    unit_mode: str = "Counts"          # "Counts" | "Concentration"
    channels: list = field(default_factory=list)
    temperature: Optional[float] = None
    temp_unit: str = "NA"
    humidity: Optional[float] = None
    velocity: Optional[float] = None
    flow: Optional[float] = None
    co2: Optional[float] = None
    device_status: int = 0
    data_valid: bool = True
    flow_ok: bool = True
    laser_ok: bool = True
    optics_dirty: bool = False
    scatter_alert: bool = False
    calibration_corrupt: bool = False
    service_alert: bool = False
    precision_flow_rate: float = 0.0
    measurement_enabled: int = 0


@dataclass
class TSIDevice:
    ip: str
    port: int = PORT
    model: str = ""
    serial: str = ""
    num_channels: int = 8
    num_records: int = 0
    firmware_version: int = 0
    flow_unit: str = "CFM"
    nominal_flow: float = 0.0
    has_data_integrity: bool = False
    viable_counts: bool = False
    num_locations: int = 10
    num_recipes: int = 10
    num_zones: int = 0
    channel_sizes: list = field(default_factory=list)
    locations: dict = field(default_factory=dict)
    recipes: dict = field(default_factory=dict)
    records: list = field(default_factory=list)


# ─── Connessione e lettura ────────────────────────────────────────────────────

class TSIClient:
    """Client Modbus TCP per strumenti TSI (particle counter serie 9xxx)."""

    def __init__(self, ip: str, port: int = PORT, timeout: float = TIMEOUT):
        self.ip = ip
        self.port = port
        self.timeout = timeout
        self._sock: Optional[socket.socket] = None

    def connect(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.settimeout(self.timeout)
        self._sock.connect((self.ip, self.port))
        log.info(f"Connesso a {self.ip}:{self.port}")

    def disconnect(self):
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None

    def _send_recv(self, packet: bytes, buf_size: int = 4096) -> bytes:
        self._sock.sendall(packet)
        return self._sock.recv(buf_size)

    def _write_then_read(self, write_pkt: bytes, read_pkt: bytes, buf_size: int = 4096) -> bytes:
        self._sock.sendall(write_pkt)
        self._sock.recv(64)          # ack scrittura (6 byte tipici)
        self._sock.sendall(read_pkt)
        return self._sock.recv(buf_size)

    # ── Lettura info device ──────────────────────────────────────────────────

    def read_device_info(self) -> dict:
        """
        Legge i registri device info (equivale a A_READ_DEVICE_INFO nel C#).
        Registro base: 41003 (0-based: 41003-40001 = 1002), lunghezza 60 reg.
        """
        pkt = _modbus_read(1, _binary_address(41003), 60)
        resp = self._send_recv(pkt)
        if len(resp) < 9:
            raise IOError("Risposta troppo corta per device info")

        # il payload Modbus inizia all'offset 9 (dopo header MBAP + unit + fc + bytecount)
        msg = bytearray(resp)
        byte_count = msg[8]
        data_start = 9

        info = {}
        idx = data_start

        # FirmwareVersion (uint16 swap)
        info["firmware_version"] = _swap_and_read_u16(msg, idx); idx += 2
        # Model (16 byte ASCII)
        model_bytes = bytearray(msg[idx:idx + 16])
        for i in range(0, 16, 2):
            model_bytes[i], model_bytes[i + 1] = model_bytes[i + 1], model_bytes[i]
        info["model"] = model_bytes.decode("ascii", errors="ignore").rstrip("\x00").strip()
        idx += 16
        # Serial (16 byte ASCII)
        serial_bytes = bytearray(msg[idx:idx + 16])
        for i in range(0, 16, 2):
            serial_bytes[i], serial_bytes[i + 1] = serial_bytes[i + 1], serial_bytes[i]
        info["serial"] = serial_bytes.decode("ascii", errors="ignore").rstrip("\x00").strip()
        idx += 16
        idx += 16  # algorithm id skip

        # LastCalibrationDate: year, month, day (3× uint16)
        y = _swap_and_read_u16(msg, idx); idx += 2
        mo = _swap_and_read_u16(msg, idx); idx += 2
        d = _swap_and_read_u16(msg, idx); idx += 2
        try:
            info["last_calibration_date"] = datetime(y, mo, d).isoformat()
        except Exception:
            info["last_calibration_date"] = None
        # CalibrationDueDate
        y2 = _swap_and_read_u16(msg, idx); idx += 2
        mo2 = _swap_and_read_u16(msg, idx); idx += 2
        d2 = _swap_and_read_u16(msg, idx); idx += 2
        try:
            info["calibration_due_date"] = datetime(y2, mo2, d2).isoformat()
        except Exception:
            info["calibration_due_date"] = None

        # NominalFlowRate
        fr_raw = _swap_and_read_u16(msg, idx); idx += 2
        flow_unit_bit = (fr_raw & 0x8000) != 0
        info["nominal_flow_rate"] = (fr_raw & 0x7FFF) / 100.0
        info["flow_unit"] = "LPM" if flow_unit_bit else "CFM"

        # NumberOfChannels
        info["num_channels"] = _swap_and_read_u16(msg, idx); idx += 2
        # DeviceFeatures
        dev_feat = _swap_and_read_u16(msg, idx); idx += 2
        info["variable_bins"] = bool(dev_feat & 512)
        info["unicode"] = bool(dev_feat & 8192)
        info["handheld"] = bool(dev_feat & 1)

        # ChannelSizes (16× uint16)
        sizes = []
        for _ in range(16):
            sizes.append(_swap_and_read_u16(msg, idx)); idx += 2
        info["channel_sizes"] = sizes

        # DeviceFeatures2
        if idx < data_start + byte_count:
            dev_feat2 = _swap_and_read_u16(msg, idx); idx += 2
            info["viable_counts"] = bool(dev_feat2 & 1)
            info["has_data_integrity"] = bool(dev_feat2 & 16)
        idx += 16  # skip padding/reserved

        # supportedMeasurements, numLocations, locationLabelLength, numRecipes, recipeLabelLength
        if idx + 10 <= data_start + byte_count:
            info["supported_measurements"] = _swap_and_read_u16(msg, idx); idx += 2
            idx += 6  # skip 3 unused
            info["num_locations"] = _swap_and_read_u16(msg, idx); idx += 2
            idx += 2
            info["num_recipes"] = _swap_and_read_u16(msg, idx); idx += 2

        return info

    def read_model(self) -> str:
        """Legge il model (40003, 8 reg)."""
        pkt = _modbus_read(1, _binary_address(40003), 8)
        resp = bytearray(self._send_recv(pkt))
        if len(resp) < 9 + 16:
            return ""
        for i in range(9, 9 + 16, 2):
            resp[i], resp[i + 1] = resp[i + 1], resp[i]
        return resp[9:9 + 16].decode("ascii", errors="ignore").rstrip("\x00").strip()

    def read_serial(self) -> str:
        """Legge il serial (40011, 8 reg)."""
        pkt = _modbus_read(1, _binary_address(40011), 8)
        resp = bytearray(self._send_recv(pkt))
        if len(resp) < 9 + 16:
            return ""
        byte_count = resp[8]
        for i in range(9, 9 + byte_count, 2):
            resp[i], resp[i + 1] = resp[i + 1], resp[i]
        return resp[9:9 + byte_count].decode("ascii", errors="ignore").rstrip("\x00").strip()

    def read_num_samples(self) -> int:
        """Legge il numero di campioni memorizzati (42001, 2 reg → uint32)."""
        pkt = _modbus_read(1, _binary_address(42001), 2)
        resp = bytearray(self._send_recv(pkt))
        if len(resp) < 13:
            return 0
        b = bytearray(resp[9:13])
        b.reverse()
        return struct.unpack(">I", b)[0]

    # ── Lettura record ───────────────────────────────────────────────────────

    def _write_record_index(self, index: int):
        """Scrive l'indice del record (41078 hi, 41079 lo)."""
        b = struct.pack(">I", index)
        hi = struct.unpack(">H", b[0:2])[0]
        lo = struct.unpack(">H", b[2:4])[0]
        pkt_hi = _modbus_write_single(1, _binary_address(41078), hi)
        pkt_lo = _modbus_write_single(1, _binary_address(41079), lo)
        self._sock.sendall(pkt_hi)
        self._sock.recv(64)
        self._sock.sendall(pkt_lo)
        self._sock.recv(64)

    def read_record(self, index: int, num_channels: int = 8,
                    has_data_integrity: bool = False) -> Optional[TSIRecord]:
        """Legge un singolo record di campione dallo strumento."""
        self._write_record_index(index)
        length = (42123 if has_data_integrity else 42122) - 42005 + 1
        if length > 125:
            length = 118  # fallback sicuro
        pkt = _modbus_read(1, _binary_address(42005), length)
        resp = bytearray(self._send_recv(pkt, 512))
        if len(resp) < 9:
            return None
        return self._parse_record(resp, num_channels, has_data_integrity)

    def _parse_record(self, msg: bytearray, num_channels: int,
                      has_data_integrity: bool) -> TSIRecord:
        """
        Traduzione di ModbusInterpreter.InterpretRecord in Python.
        Il payload Modbus inizia all'offset 9 nel buffer ricevuto.
        """
        BASE = 9  # inizio dati Modbus nel buffer

        # recNum (uint32 swap)
        b = bytearray(msg[BASE:BASE + 4]); b.reverse()
        rec_num = struct.unpack(">I", b)[0]

        # DateTime: year, month, day, hour, minute, second (6× uint16 swap)
        dt_vals = []
        off = BASE + 4
        for _ in range(6):
            v = struct.unpack(">H", bytes(msg[off:off + 2]))[0]; off += 2
            dt_vals.append(v)
        try:
            ts = datetime(*dt_vals)
        except Exception:
            ts = datetime.utcnow()

        off += 4  # skip 4 byte (padding nel C#)

        # ViableDetectionSensitivity
        b2 = bytearray(msg[off:off + 2]); b2.reverse()
        viable_sens = struct.unpack(">H", b2)[0]; off += 2

        # PrecisionFlowRate (float32 swap)
        bf = bytearray(msg[off:off + 4]); bf.reverse()
        precision_flow = struct.unpack(">f", bf)[0]; off += 4

        # DeviceStatus (uint16)
        b3 = bytearray(msg[off:off + 2]); b3.reverse()
        dev_status = struct.unpack(">H", b3)[0]; off += 2
        flow_ok = (dev_status & 1) == 0
        flow_stopped = (dev_status & 2) != 0
        laser_ok = (dev_status & 4) == 0
        scatter_alert = (dev_status & 8) != 0
        optics_dirty = (dev_status & 16) != 0
        cal_corrupt = (dev_status & 32) != 0
        service_alert = (dev_status & 16384) != 0
        data_valid = (dev_status & 32768) == 0

        # chAlarm bitmask
        b4 = bytearray(msg[off:off + 2]); b4.reverse()
        ch_alarm_mask = struct.unpack(">H", b4)[0]; off += 2
        ch_alarms = [(ch_alarm_mask >> y) & 1 != 0 for y in range(16)]

        # flowRateX100 + flowType bit15
        b5 = bytearray(msg[off:off + 2]); b5.reverse()
        flow_raw = struct.unpack(">H", b5)[0]; off += 2
        flow_type = "LPM" if (flow_raw & 0x8000) else "CFM"
        flow_rate_x100 = flow_raw & 0x7FFF

        # sampleTime value (uint32 swap)
        b6 = bytearray(msg[off:off + 4]); b6.reverse()
        sample_time_val = struct.unpack(">I", b6)[0]; off += 4

        # timeUnit (uint16)
        b7 = bytearray(msg[off:off + 2]); b7.reverse()
        time_unit = struct.unpack(">H", b7)[0]; off += 2
        if time_unit == 0:
            sample_time_sec = sample_time_val // 1000
        else:
            sample_time_sec = sample_time_val

        # countMode / unitMode
        b8 = bytearray(msg[off:off + 2]); b8.reverse()
        mode_raw = struct.unpack(">H", b8)[0]; off += 2
        count_mode = "Differential" if (mode_raw & 0xFF00) == 0 else "Cumulative"
        unit_mode = "Counts" if (mode_raw & 0x00FF) == 0 else "Concentration"

        # locNumber
        b9 = bytearray(msg[off:off + 2]); b9.reverse()
        loc_num = struct.unpack(">H", b9)[0]; off += 2

        # counts[16] (uint32 × 16 = 64 bytes)
        counts = []
        for _ in range(16):
            bc = bytearray(msg[off:off + 4]); bc.reverse()
            counts.append(struct.unpack(">I", bc)[0]); off += 4

        # chSizes[16] (uint16 × 16 = 32 bytes)
        ch_sizes = []
        for _ in range(16):
            bs = bytearray(msg[off:off + 2]); bs.reverse()
            ch_sizes.append(struct.unpack(">H", bs)[0]); off += 2

        # measurementEnabled (vicino alla fine)
        byte_count = msg[8] if len(msg) > 8 else 0
        meas_offset = BASE + (byte_count - 4 if has_data_integrity else byte_count - 2)
        measurement_enabled = 0
        if meas_offset >= 0 and meas_offset + 2 <= len(msg):
            bm = bytearray(msg[meas_offset:meas_offset + 2]); bm.reverse()
            measurement_enabled = struct.unpack(">H", bm)[0]

        # misure ambientali opzionali
        temperature = humidity = velocity = flow_env = co2 = None
        temp_unit = "NA"

        if measurement_enabled & 1:  # temperatura
            btu = bytearray(msg[off:off + 2]); btu.reverse()
            temp_unit_code = struct.unpack(">H", btu)[0]; off += 2
            temp_unit = {0x43: "C", 0x46: "F"}.get(temp_unit_code, "NA")
            btv = bytearray(msg[off:off + 4]); btv.reverse()
            temperature = struct.unpack(">f", btv)[0]; off += 4

        if measurement_enabled & 2:  # humidity
            off += 2  # unit code
            bh = bytearray(msg[off:off + 4]); bh.reverse()
            humidity = struct.unpack(">f", bh)[0]; off += 4

        if measurement_enabled & 4:  # velocity
            off += 2
            bv = bytearray(msg[off:off + 4]); bv.reverse()
            velocity = struct.unpack(">f", bv)[0]; off += 4

        if measurement_enabled & 8:  # flow
            off += 2
            bfl = bytearray(msg[off:off + 4]); bfl.reverse()
            flow_env = struct.unpack(">f", bfl)[0]; off += 4

        if measurement_enabled & 16:  # CO2
            off += 2
            bc2 = bytearray(msg[off:off + 4]); bc2.reverse()
            co2 = struct.unpack(">f", bc2)[0]; off += 4

        # Costruzione canali (solo i num_channels validi)
        channels = []
        for i in range(min(num_channels, 16)):
            channels.append(TSIChannel(
                size_um=ch_sizes[i] / 1000.0,
                count=counts[i],
                alarm=ch_alarms[i]
            ))

        return TSIRecord(
            rec_num=rec_num,
            timestamp=ts,
            location_id=loc_num,
            flow_rate=flow_rate_x100 / 100.0,
            flow_type=flow_type,
            sample_time_sec=sample_time_sec,
            count_mode=count_mode,
            unit_mode=unit_mode,
            channels=channels,
            temperature=temperature,
            temp_unit=temp_unit,
            humidity=humidity,
            velocity=velocity,
            flow=flow_env,
            co2=co2,
            device_status=dev_status,
            data_valid=data_valid,
            flow_ok=flow_ok,
            laser_ok=laser_ok,
            optics_dirty=optics_dirty,
            scatter_alert=scatter_alert,
            calibration_corrupt=cal_corrupt,
            service_alert=service_alert,
            precision_flow_rate=precision_flow,
            measurement_enabled=measurement_enabled,
        )

    # ── Lettura location labels ──────────────────────────────────────────────

    def read_location_labels(self, num_locations: int) -> dict:
        """Legge le etichette di tutte le location (come ReadLocationLabels nel C#)."""
        locations = {}
        write_reg = _binary_address(43001)
        read_pkt = _modbus_read(1, _binary_address(43001), 17)
        for i in range(1, num_locations + 1):
            write_pkt = _modbus_write_single(1, write_reg, i)
            resp = bytearray(self._write_then_read(write_pkt, read_pkt))
            if len(resp) < 9 + 34:
                continue
            # byte count, poi swap a coppie
            bc = resp[8]
            for j in range(9, 9 + bc, 2):
                if j + 1 < len(resp):
                    resp[j], resp[j + 1] = resp[j + 1], resp[j]
            loc_id = struct.unpack(">H", resp[9:11])[0]
            name_bytes = resp[11:11 + 32]
            name = name_bytes.decode("ascii", errors="ignore").split("\x00")[0].strip()
            if name:
                locations[loc_id] = name
        return locations

    # ── Comandi strumento ────────────────────────────────────────────────────
    #
    # Tutti i comandi scrivono il codice nel registro 41001 (CommandRegister).
    # Codici estratti da TSIModbusRegisterMap.cs:
    #   CMD_CLEAR_DATA        = 1   → cancella tutti i record dallo strumento
    #   CMD_START_PUMP        = 2   → avvia pompa (pre-campionamento)
    #   CMD_MANUAL_START      = 3   → avvia misura manuale
    #   CMD_MANUAL_STOP       = 4   → ferma misura manuale
    #   CMD_STOP_PUMP         = 5   → ferma pompa
    #   CMD_AUTO_START        = 6   → avvia ciclo automatico (da recipe)
    #   CMD_AUTO_STOP         = 7   → ferma ciclo automatico
    #   CMD_SET_RTC           = 8   → sincronizza orologio
    #   CMD_DISABLE_LOCAL_CTL = 12  → disabilita controllo locale (display)
    #   CMD_ENABLE_LOCAL_CTL  = 13  → riabilita controllo locale
    #   CMD_SILENCE_DEVICE    = 14  → silenzia allarme acustico
    #   CMD_UNSILENCE_DEVICE  = 15  → riabilita allarme acustico
    #   CMD_PURGE_START       = 30  → avvia purge (pulizia ottica)
    #   CMD_REBOOT_UNIT       = 29  → riavvia lo strumento

    CMD_CLEAR_DATA        = 1
    CMD_START_PUMP        = 2
    CMD_MANUAL_START      = 3
    CMD_MANUAL_STOP       = 4
    CMD_STOP_PUMP         = 5
    CMD_AUTO_START        = 6
    CMD_AUTO_STOP         = 7
    CMD_SET_RTC           = 8
    CMD_DISABLE_LOCAL_CTL = 12
    CMD_ENABLE_LOCAL_CTL  = 13
    CMD_SILENCE_DEVICE    = 14
    CMD_UNSILENCE_DEVICE  = 15
    CMD_REBOOT_UNIT       = 29
    CMD_PURGE_START       = 30

    # Registro stato (41002): letto per sapere se lo strumento è occupato
    # STAT_STOPPED      = 0  → idle
    # STAT_START_DELAY  = 1  → in hold time / pre-delay
    # STAT_SAMPLING     = altri valori → in campionamento
    REG_COMMAND = 41001
    REG_STATUS  = 41002

    def _send_command(self, cmd_code: int) -> bool:
        """
        Scrive cmd_code nel registro 41001 (CommandRegister).
        Restituisce True se il device ha risposto correttamente.
        """
        pkt = _modbus_write_single(1, _binary_address(self.REG_COMMAND), cmd_code)
        resp = self._send_recv(pkt, 64)
        # una risposta FC6 valida ha almeno 12 byte
        return len(resp) >= 6

    def read_status(self) -> dict:
        """
        Legge il registro di stato (41002).
        Restituisce dict con 'raw', 'state', 'description'.

        Bit noti dal C# (DeviceStatus in ModbusMap2Record):
          bit 0  → flow error
          bit 1  → flow stopped
          bit 2  → laser error
          bit 3  → scatter alert
          bit 4  → optics dirty
          bit 5  → calibration corrupt
          bit 14 → service alert
          bit 15 → data invalid
        """
        pkt = _modbus_read(1, _binary_address(self.REG_STATUS), 1)
        resp = bytearray(self._send_recv(pkt, 64))
        if len(resp) < 11:
            return {"raw": None, "state": "unknown", "description": "No response"}
        b = bytearray(resp[9:11]); b.reverse()
        raw = struct.unpack(">H", b)[0]
        # Lo stato principale è nei bit alti del registro di status
        state_map = {
            0: "stopped",
            1: "start_delay",
            2: "sampling",
            3: "manual_sampling",
            4: "purging",
        }
        state_code = (raw >> 8) & 0x0F
        state = state_map.get(state_code, f"unknown({state_code})")
        return {
            "raw": raw,
            "state": state,
            "sampling": state not in ("stopped", "unknown"),
            "flow_error":     bool(raw & 0x0001),
            "flow_stopped":   bool(raw & 0x0002),
            "laser_error":    bool(raw & 0x0004),
            "scatter_alert":  bool(raw & 0x0008),
            "optics_dirty":   bool(raw & 0x0010),
            "cal_corrupt":    bool(raw & 0x0020),
            "service_alert":  bool(raw & 0x4000),
        }

    # ── Manutenzione ─────────────────────────────────────────────────────────

    def clear_all_data(self) -> bool:
        """
        Cancella tutti i record dallo strumento (CMD_CLEAR_DATA = 1).
        Equivale a ClearAllData() nel C#:
            Write(addr, BinaryAddress(41001), 1)
        ATTENZIONE: operazione irreversibile sullo strumento.
        """
        log.info(f"[{self.ip}] clear_all_data → CMD 1")
        return self._send_command(self.CMD_CLEAR_DATA)

    def reboot(self) -> bool:
        """Riavvia lo strumento (CMD_REBOOT_UNIT = 29)."""
        log.info(f"[{self.ip}] reboot → CMD 29")
        return self._send_command(self.CMD_REBOOT_UNIT)

    def sync_clock(self) -> bool:
        """
        Sincronizza l'orologio dello strumento con l'orario del PC (CMD_SET_RTC = 8).
        Equivale a WriteDateTime() nel C#: scrive year/month/day/hour/min/sec
        nei registri 41006–41011, poi invia CMD 8.
        """
        now = datetime.now()
        packets = [
            (41006, now.year),
            (41007, now.month),
            (41008, now.day),
            (41009, now.hour),
            (41010, now.minute),
            (41011, now.second),
        ]
        for reg, val in packets:
            pkt = _modbus_write_single(1, _binary_address(reg), val)
            self._sock.sendall(pkt)
            self._sock.recv(64)
        log.info(f"[{self.ip}] sync_clock → CMD 8 (now={now.isoformat()})")
        return self._send_command(self.CMD_SET_RTC)

    def purge_start(self) -> bool:
        """Avvia ciclo di pulizia ottica (CMD_PURGE_START = 30)."""
        log.info(f"[{self.ip}] purge_start → CMD 30")
        return self._send_command(self.CMD_PURGE_START)

    def silence(self) -> bool:
        """Silenzia l'allarme acustico (CMD_SILENCE_DEVICE = 14)."""
        return self._send_command(self.CMD_SILENCE_DEVICE)

    def unsilence(self) -> bool:
        """Riabilita l'allarme acustico (CMD_UNSILENCE_DEVICE = 15)."""
        return self._send_command(self.CMD_UNSILENCE_DEVICE)

    def disable_local_control(self) -> bool:
        """
        Disabilita il pannello locale dello strumento (CMD_DISABLE_LOCAL_CONTROL = 12).
        Usato nel C# durante letture massicce (>1000 record).
        """
        return self._send_command(self.CMD_DISABLE_LOCAL_CTL)

    def enable_local_control(self) -> bool:
        """Riabilita il pannello locale (CMD_ENABLE_LOCAL_CONTROL = 13)."""
        return self._send_command(self.CMD_ENABLE_LOCAL_CTL)

    # ── Controllo misura ──────────────────────────────────────────────────────

    def start_pump(self) -> bool:
        """
        Avvia la pompa (CMD_START_PUMP = 2).
        Tipicamente usato prima di start_manual per preriscaldare il flusso.
        """
        log.info(f"[{self.ip}] start_pump → CMD 2")
        return self._send_command(self.CMD_START_PUMP)

    def stop_pump(self) -> bool:
        """Ferma la pompa (CMD_STOP_PUMP = 5)."""
        log.info(f"[{self.ip}] stop_pump → CMD 5")
        return self._send_command(self.CMD_STOP_PUMP)

    def start_manual(self) -> bool:
        """
        Avvia una misura manuale (CMD_MANUAL_START = 3).
        Lo strumento campiona finché non riceve stop_manual().
        """
        log.info(f"[{self.ip}] start_manual → CMD 3")
        return self._send_command(self.CMD_MANUAL_START)

    def stop_manual(self) -> bool:
        """
        Ferma la misura manuale in corso (CMD_MANUAL_STOP = 4).
        Il record viene salvato nello strumento.
        """
        log.info(f"[{self.ip}] stop_manual → CMD 4")
        return self._send_command(self.CMD_MANUAL_STOP)

    def start_auto(self) -> bool:
        """
        Avvia un ciclo automatico basato sulla recipe attiva (CMD_AUTO_START = 6).
        Lo strumento esegue delay → campionamento → hold per N cicli.
        """
        log.info(f"[{self.ip}] start_auto → CMD 6")
        return self._send_command(self.CMD_AUTO_START)

    def stop_auto(self) -> bool:
        """
        Cancella il ciclo automatico in corso (CMD_AUTO_STOP = 7).
        """
        log.info(f"[{self.ip}] stop_auto → CMD 7")
        return self._send_command(self.CMD_AUTO_STOP)

    def stop_measurement(self) -> bool:
        """
        Stop generico: ferma sia misura manuale che automatica.
        Invia prima CMD_MANUAL_STOP, poi CMD_AUTO_STOP (safe: lo strumento
        ignora il comando se già fermo).
        """
        r1 = self._send_command(self.CMD_MANUAL_STOP)
        r2 = self._send_command(self.CMD_AUTO_STOP)
        return r1 or r2

    # ── Fetch completo ───────────────────────────────────────────────────────

    def fetch_all(self, max_records: int = 1000) -> TSIDevice:
        """
        Connette, legge tutte le informazioni del device e tutti i record.
        Restituisce un oggetto TSIDevice popolato.
        """
        self.connect()
        try:
            device = TSIDevice(ip=self.ip, port=self.port)
            device.model = self.read_model()
            device.serial = self.read_serial()
            device.num_records = self.read_num_samples()

            try:
                info = self.read_device_info()
                device.firmware_version = info.get("firmware_version", 0)
                device.flow_unit = info.get("flow_unit", "CFM")
                device.nominal_flow = info.get("nominal_flow_rate", 0.0)
                device.has_data_integrity = info.get("has_data_integrity", False)
                device.viable_counts = info.get("viable_counts", False)
                device.num_channels = info.get("num_channels", 8)
                device.num_locations = info.get("num_locations", 10)
                device.num_recipes = info.get("num_recipes", 10)
                device.channel_sizes = info.get("channel_sizes", [])
            except Exception as e:
                log.warning(f"read_device_info fallita: {e}")

            try:
                device.locations = self.read_location_labels(device.num_locations)
            except Exception as e:
                log.warning(f"read_location_labels fallita: {e}")

            to_read = min(device.num_records, max_records)
            log.info(f"Lettura {to_read} record su {device.num_records} totali")
            for i in range(to_read):
                try:
                    rec = self.read_record(i, device.num_channels, device.has_data_integrity)
                    if rec:
                        rec.location_name = device.locations.get(rec.location_id, "")
                        device.records.append(rec)
                except Exception as e:
                    log.warning(f"Errore lettura record {i}: {e}")
            return device
        finally:
            self.disconnect()
