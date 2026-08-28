# ruff: noqa: E402, INP001, RUF001, T201
"""Inspect a real Midea AC and capture power/energy protocol traffic."""

import argparse
import contextlib
import io
import logging
import sys
import time
from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime
from pathlib import Path
from typing import Any, TextIO

# Allow direct execution from a source checkout without requiring an editable install.
REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from midealan.const import DeviceType
from midealan.devices import device_selector
from midealan.devices.ac.message import (
    GroupOneQuery,
    GroupSevenQuery,
    GroupTwoQuery,
    GroupZeroQuery,
    HumidityQuery,
    PowerQuery,
    SubProtocolQuery4C,
    SubProtocolQuery10RunStatus,
    SubProtocolQuery10RunStatus2,
    SubProtocolQuery15,
    SubProtocolQuery51,
)
from midealan.discover import discover

_LOGGER = logging.getLogger(__name__)

TOKEN_HEX_LENGTH = 128
KEY_HEX_LENGTH = 64
DEFAULT_SAMPLE_COUNT = 18
DEFAULT_SAMPLE_INTERVAL = 10.0
DEFAULT_SESSION_LOG = Path("midea_ac_live.log")
DEFAULT_RAW_LOG = Path("midea_ac_power_raw.log")
MESSAGE_BODY_START = 10
MESSAGE_CHECKSUM_LENGTH = 1
BB_BODY_TYPE = 0xBB
BB_HEADER_LENGTH = 6
BB_GROUP_INDEX = 5
BB_INDOOR_GROUP = 0x10
BB_OUTDOOR_GROUP = 0x30
BB_FEATURE_GROUP = 0x4C
BB_ELECTRICITY_CAPABILITY_GROUP = 0x51
BB_X10_ENERGY_NEED_INDEX = 13
BB_X10_TOTAL_ELEC_START = 46
BB_X10_TOTAL_ELEC_END = 50
BB_X30_ELECTRICITY_QUERY_FLAGS_INDEX = 91
BB_X30_ELECTRICITY_QUERY_SUPPORTED_MASK = 0x01
BB_X4C_SOLAR_CAPABILITY_INDEX = 11
BB_X4C_SOLAR_CAPABILITY_MASK = 0x04
BB_X4C_SOLAR_POWER_START = 12
BB_X4C_SOLAR_POWER_END = 16
BB_X51_MESSAGE_TYPE_INDEX = 0
BB_X51_SUPPORTED_MESSAGE_TYPES = (0x03, 0x04)
BB_X51_ELECTRICITY_QUERY_FLAGS_INDEX = 6
BB_X51_ELECTRICITY_QUERY_SUPPORTED_MASK = 0x02
C1_BODY_TYPE = 0xC1
C1_GROUP_INDEX = 3
C1_ENERGY_GROUP = 0x44
C1_OUTDOOR_POWER_GROUP = 0x47
C1_GROUP_LABELS = {
    0x40: "0x40 运行时长",
    0x41: "0x41 压缩机电参",
    0x42: "0x42 室内风机/水泵",
    C1_ENERGY_GROUP: "0x44 实时/累计能耗",
    0x45: "0x45 湿度",
    C1_OUTDOOR_POWER_GROUP: "0x47 外机功率",
}
C1_PROBES = (
    (GroupZeroQuery, 0x40),
    (GroupOneQuery, 0x41),
    (GroupTwoQuery, 0x42),
    (PowerQuery, C1_ENERGY_GROUP),
    (HumidityQuery, 0x45),
    (GroupSevenQuery, C1_OUTDOOR_POWER_GROUP),
)

POWER_SAMPLE_FIELDS = (
    "power",
    "mode",
    "outdoor_temperature",
    "compressor_frequency",
    "target_compressor_frequency",
    "compressor_power",
    "realtime_power",
    "total_energy_consumption",
    "current_energy_consumption",
    "total_operating_consumption",
    "electrify_time",
    "total_operating_time",
    "current_operating_time",
    "compressor_current",
    "compressor_voltage",
)

GENERAL_STATUS_FIELDS = (
    "power",
    "mode",
    "target_temperature",
    "min_temperature",
    "max_temperature",
    "fan_speed",
    "swing_vertical",
    "swing_horizontal",
    "boost_mode",
    "eco_mode",
    "aux_heating",
    "sleep_mode",
    "breezeless",
    "self_clean",
    "rate_select",
    "error_code",
)

INDOOR_STATUS_FIELDS = (
    "indoor_temperature",
    "indoor_humidity",
    "indoor_ambient_temperature",
    "indoor_coil_temperature",
    "indoor_fan_speed",
    "target_indoor_fan_speed",
    "water_pump_running",
    "fresh_air_power",
    "fresh_air_fan_speed",
    "fresh_air_mode",
    "fresh_air_exhaust_power",
    "fresh_air_exhaust_speed",
    "fresh_air_exhaust_mode",
)

OUTDOOR_STATUS_FIELDS = (
    "outdoor_temperature",
    "outdoor_ambient_temperature",
    "outdoor_coil_temperature",
    "discharge_pipe_temperature",
    "compressor_frequency",
    "target_compressor_frequency",
    "compressor_current",
    "compressor_voltage",
    "compressor_power",
    "out_silent",
)

ENERGY_STATUS_FIELDS = (
    "total_energy_consumption",
    "total_operating_consumption",
    "current_energy_consumption",
    "realtime_power",
    "electrify_time",
    "total_operating_time",
    "current_operating_time",
)


class TeeTextStream(io.TextIOBase):
    """Mirror terminal output into the persistent session log."""

    def __init__(self, terminal: TextIO, log_file: TextIO) -> None:
        """Initialize the mirrored stream."""
        self._terminal = terminal
        self._log_file = log_file

    def write(self, text: str) -> int:
        """Write text to both destinations."""
        written = self._terminal.write(text)
        self._log_file.write(text)
        self._log_file.flush()
        return written

    def flush(self) -> None:
        """Flush both destinations."""
        self._terminal.flush()
        self._log_file.flush()

    def isatty(self) -> bool:
        """Preserve terminal detection for logging and tracebacks."""
        return self._terminal.isatty()


def parse_hex_credential(value: str, name: str, expected_length: int) -> str:
    """Validate and normalize one hexadecimal LAN credential."""
    credential = value.strip().lower()
    if len(credential) != expected_length:
        message = f"{name} 必须是 {expected_length} 个十六进制字符"
        raise argparse.ArgumentTypeError(message)
    try:
        bytes.fromhex(credential)
    except ValueError as error:
        message = f"{name} 只能包含十六进制字符 0-9、a-f"
        raise argparse.ArgumentTypeError(message) from error
    return credential


def parse_token(value: str) -> str:
    """Parse a 64-byte V3 token."""
    return parse_hex_credential(value, "token", TOKEN_HEX_LENGTH)


def parse_key(value: str) -> str:
    """Parse a 32-byte V3 key."""
    return parse_hex_credential(value, "key", KEY_HEX_LENGTH)


def positive_int(value: str) -> int:
    """Parse a positive integer command-line value."""
    parsed = int(value)
    if parsed < 1:
        message = "数值必须大于等于 1"
        raise argparse.ArgumentTypeError(message)
    return parsed


def nonnegative_float(value: str) -> float:
    """Parse a nonnegative floating-point command-line value."""
    parsed = float(value)
    if parsed < 0:
        message = "数值不能小于 0"
        raise argparse.ArgumentTypeError(message)
    return parsed


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="连接真实美的空调，检测功率/能耗并保存完整协议日志。",
    )
    parser.add_argument("--host", required=True, help="空调的局域网 IP 地址")
    parser.add_argument(
        "--token",
        required=True,
        type=parse_token,
        help="设备的 128 个十六进制字符 token",
    )
    parser.add_argument(
        "--key",
        required=True,
        type=parse_key,
        help="设备的 64 个十六进制字符 key",
    )
    parser.add_argument(
        "--subtype",
        type=int,
        default=0,
        help="设备 subtype（默认：0）",
    )
    parser.add_argument(
        "--samples",
        type=positive_int,
        default=DEFAULT_SAMPLE_COUNT,
        help=f"采样次数（默认：{DEFAULT_SAMPLE_COUNT}）",
    )
    parser.add_argument(
        "--interval",
        type=nonnegative_float,
        default=DEFAULT_SAMPLE_INTERVAL,
        help=f"采样间隔秒数（默认：{DEFAULT_SAMPLE_INTERVAL:g}）",
    )
    parser.add_argument(
        "--show-all",
        action="store_true",
        help="输出全部 attributes，包括值为 None 的字段",
    )
    parser.add_argument(
        "--all-c1-probes",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="BB 模式下额外发送 C1 0x40/41/42/44/45/47 只读查询（默认启用）",
    )
    parser.add_argument(
        "--bb-status-variants",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="发送 Lua 已知的 BB 0x10/0x01、0x10/0x02 及 0x15/4C/51 查询（默认启用）",
    )
    parser.add_argument(
        "--power-query",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="额外探测定长 C1 0x44 功率/能耗（默认启用）",
    )
    parser.add_argument(
        "--group-seven",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="额外探测定长 C1 0x47 外机功率（默认启用）",
    )
    parser.add_argument(
        "--log-level",
        choices=("DEBUG", "INFO", "WARNING"),
        default="DEBUG",
        help="完整会话日志级别（默认：DEBUG）",
    )
    parser.add_argument(
        "--log-file",
        type=Path,
        default=DEFAULT_SESSION_LOG,
        help=f"终端及库日志文件（默认：{DEFAULT_SESSION_LOG}）",
    )
    parser.add_argument(
        "--raw-log",
        type=Path,
        default=DEFAULT_RAW_LOG,
        help=f"解密后的 TX/RX 原始日志（默认：{DEFAULT_RAW_LOG}）",
    )
    return parser.parse_args(argv)


class RawPowerRecorder:
    """Record decrypted query and response data without LAN credentials."""

    def __init__(self, path: Path) -> None:
        """Start one append-only capture session."""
        self.path = path
        self.x10_samples: list[bytes] = []
        self.x30_samples: list[bytes] = []
        self.x4c_samples: list[bytes] = []
        self.x51_samples: list[bytes] = []
        self.bb_samples: dict[int, list[bytes]] = {}
        self.c1_samples: dict[int, list[bytes]] = {}
        self.query_power_states: dict[str, list[Any]] = {}
        self._write(
            "\n"
            + "=" * 72
            + f"\nsession_start={self.timestamp()}\n"
            + "注意：日志不含 token/key，但包含设备状态原始数据。\n",
        )

    @staticmethod
    def timestamp() -> str:
        """Return a local timestamp with millisecond precision."""
        return datetime.now().astimezone().isoformat(timespec="milliseconds")

    def _write(self, text: str) -> None:
        """Append text to the capture file."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as log_file:
            log_file.write(text)

    @staticmethod
    def _indexed(payload: bytes) -> str:
        """Format every byte with its decimal index."""
        return " ".join(
            f"{index:02d}:{value:02x}" for index, value in enumerate(payload)
        )

    def record_query(
        self,
        query_name: str,
        attributes: Mapping[str, Any],
        body: bytes,
    ) -> None:
        """Record query identity and its unencrypted appliance body."""
        self.query_power_states.setdefault(query_name, []).append(
            attributes.get("power"),
        )
        state = " ".join(
            f"{name}={attributes.get(name)!r}" for name in POWER_SAMPLE_FIELDS
        )
        self._write(
            f"{self.timestamp()} TX query={query_name} body_len={len(body)}\n"
            f"  body_hex={body.hex()}\n"
            f"  body_indexed={self._indexed(body)}\n"
            f"  state_before={state}\n",
        )

    def record_response(
        self,
        message: bytes,
        attributes: Mapping[str, Any],
    ) -> None:
        """Record every decrypted appliance response and classify power groups."""
        body = message[MESSAGE_BODY_START:-MESSAGE_CHECKSUM_LENGTH]
        if not body:
            self._write(
                f"{self.timestamp()} RX empty_body message_hex={message.hex()}\n",
            )
            return

        state = " ".join(
            f"{name}={attributes.get(name)!r}" for name in POWER_SAMPLE_FIELDS
        )
        body_type = body[0]
        label = f"body_type=0x{body_type:02X}"

        if len(body) >= BB_HEADER_LENGTH and body_type == BB_BODY_TYPE:
            group = body[BB_GROUP_INDEX]
            subbody = bytes(body[BB_HEADER_LENGTH:])
            label += f" BB_group=0x{group:02X} subbody_len={len(subbody)}"
            self.bb_samples.setdefault(group, []).append(subbody)
            if group == BB_INDOOR_GROUP:
                self.x10_samples.append(subbody)
            elif group == BB_OUTDOOR_GROUP:
                self.x30_samples.append(subbody)
            elif group == BB_FEATURE_GROUP:
                self.x4c_samples.append(subbody)
            elif group == BB_ELECTRICITY_CAPABILITY_GROUP:
                self.x51_samples.append(subbody)
        elif len(body) > C1_GROUP_INDEX and body_type == C1_BODY_TYPE:
            group = body[C1_GROUP_INDEX]
            label += f" C1_group=0x{group:02X}"
            self.c1_samples.setdefault(group, []).append(bytes(body))

        self._write(
            f"{self.timestamp()} RX {label} body_len={len(body)}\n"
            f"  message_hex={message.hex()}\n"
            f"  body_hex={body.hex()}\n"
            f"  body_indexed={self._indexed(body)}\n"
            f"  parsed_state={state}\n",
        )

    def print_x30_changes(self) -> None:
        """Print byte positions that changed across equal-length X30 samples."""
        print("\n[BB 0x30 原始采样分析]")
        if not self.x30_samples:
            print("  没有收到 BB 0x30 响应。")
            return

        lengths = {len(sample) for sample in self.x30_samples}
        print(f"  收到 {len(self.x30_samples)} 条，长度: {sorted(lengths)}")
        comparable = [
            sample
            for sample in self.x30_samples
            if len(sample) == len(self.x30_samples[0])
        ]
        changed = [
            index
            for index in range(len(comparable[0]))
            if len({sample[index] for sample in comparable}) > 1
        ]
        if not changed:
            print("  本次采样中没有字节发生变化。")
            return
        print("  发生变化的 subbody 字节（十进制索引）:")
        for index in changed:
            values = " -> ".join(f"{sample[index]:02x}" for sample in comparable)
            print(f"    [{index:02d}] {values}")

    def print_bb_summary(self) -> None:
        """Print all BB response groups observed during this probe."""
        print("\n[BB 查询响应概览]")
        if not self.bb_samples:
            print("  没有收到 BB 响应。")
            return
        for group, samples in sorted(self.bb_samples.items()):
            lengths = sorted({len(sample) for sample in samples})
            print(f"  0x{group:02X}: {len(samples)} 条，subbody 长度 {lengths}")

    def print_x10_total_elec(self) -> None:
        """Print the exact-model Lua accumulator without guessing its unit."""
        values = [
            int.from_bytes(
                sample[BB_X10_TOTAL_ELEC_START:BB_X10_TOTAL_ELEC_END],
                "little",
            )
            for sample in self.x10_samples
            if len(sample) >= BB_X10_TOTAL_ELEC_END
        ]
        print("\n[BB 0x10 累积字段观察]")
        if not values:
            print("  Lua 的 total_elec[46:50] 字段未返回。")
            return
        transitions = " -> ".join(str(value) for value in values)
        print(f"  total_elec raw（LE32，Lua 命名）: {transitions}")
        print(
            "  单位未知：可能是能耗、运行时长或设备内部计数；"
            "本工具不会把它换算成 W、kWh 或小时。",
        )

    def print_c1_summary(self) -> None:
        """Report all standard C1 probes and responses."""
        print("\n[C1 标准运行时长/电参/能耗探测]")
        for query_class, group in C1_PROBES:
            query_states = self.query_power_states.get(query_class.__name__, [])
            samples = self.c1_samples.get(group, [])
            print(
                f"  {C1_GROUP_LABELS[group]}: 已发送 {len(query_states)} 次，"
                f"收到 {len(samples)} 条",
            )
            if samples:
                lengths = sorted({len(sample) for sample in samples})
                print(f"    body 长度: {lengths}；最新: {samples[-1].hex()}")

    def print_22396831_lua_fields(self) -> None:
        """Print fields defined by the exact model 22396831 Lua."""
        print("\n[型号 22396831 Lua 字段核对]")
        if self.x10_samples and len(self.x10_samples[-1]) > BB_X10_ENERGY_NEED_INDEX:
            energy_need = self.x10_samples[-1][BB_X10_ENERGY_NEED_INDEX]
            print(f"  BB 0x10 energy_need: {energy_need}（运行需求值，不是 W/kWh）")
        else:
            print("  BB 0x10 energy_need: 未返回")

        if (
            self.x30_samples
            and len(self.x30_samples[-1]) > BB_X30_ELECTRICITY_QUERY_FLAGS_INDEX
        ):
            x30_flag = bool(
                self.x30_samples[-1][BB_X30_ELECTRICITY_QUERY_FLAGS_INDEX]
                & BB_X30_ELECTRICITY_QUERY_SUPPORTED_MASK,
            )
            print(f"  BB 0x30 has_elec_query_30: {x30_flag}")
        else:
            print("  BB 0x30 has_elec_query_30: 未返回")

        x51 = self.x51_samples[-1] if self.x51_samples else b""
        if (
            len(x51) > BB_X51_ELECTRICITY_QUERY_FLAGS_INDEX
            and x51[BB_X51_MESSAGE_TYPE_INDEX] in BB_X51_SUPPORTED_MESSAGE_TYPES
        ):
            x51_flag = bool(
                x51[BB_X51_ELECTRICITY_QUERY_FLAGS_INDEX]
                & BB_X51_ELECTRICITY_QUERY_SUPPORTED_MASK,
            )
            print(f"  BB 0x51 has_elec_query: {x51_flag}")
        else:
            print("  BB 0x51 has_elec_query: 未返回")

        x4c = self.x4c_samples[-1] if self.x4c_samples else b""
        if len(x4c) >= BB_X4C_SOLAR_POWER_END:
            has_solar_power = bool(
                x4c[BB_X4C_SOLAR_CAPABILITY_INDEX] & BB_X4C_SOLAR_CAPABILITY_MASK,
            )
            solar_raw = x4c[BB_X4C_SOLAR_POWER_START:BB_X4C_SOLAR_POWER_END]
            print(
                f"  BB 0x4C has_solar_controller_rate_display: {has_solar_power}",
            )
            print(
                "  BB 0x4C solar_module_outdoor_total_power raw: "
                f"{solar_raw.hex()}（光伏模块字段，不是压缩机功率）",
            )
        else:
            print("  BB 0x4C 光伏模块字段: 未返回")

        print("  Lua 未定义 C1 电参的解析；本次仍会发送标准 C1 查询作交叉验证。")


def print_capabilities(capabilities: Mapping[str, bool]) -> None:
    """Print capability flags explicitly advertised in B5 responses."""
    print("\n[B5 能力声明]")
    if not capabilities:
        print("  未取得 B5 能力数据（BB 子协议设备或不响应 B5 时属于正常情况）")
        return
    for name, supported in sorted(capabilities.items()):
        state = "支持" if supported else "不支持"
        print(f"  {name}: {state}")


def print_status_group(
    title: str,
    attributes: Mapping[str, Any],
    fields: Iterable[str],
) -> None:
    """Print observed values and retain unknown fields as unknown."""
    print(f"\n[{title}]")
    reported = False
    unknown = []
    for name in fields:
        value = attributes.get(name)
        if value is None:
            unknown.append(name)
        else:
            reported = True
            print(f"  {name}: {value}")
    if not reported:
        print("  没有收到这一组的有效数据")
    if unknown:
        print("  未返回/未知: " + ", ".join(unknown))


def print_device_report(device: Any, *, show_all: bool) -> None:  # noqa: ANN401
    """Print one AC device report."""
    print("\n" + "=" * 72)
    print(f"device_id: {device.device_id}")
    print(f"model: {device.model}")
    print(f"subtype: {device.subtype}")
    print(f"serial_number: {device.serial_number or '未知'}")
    print(f"ip_address: {device._ip_address}")  # noqa: SLF001
    uses_bb = bool(getattr(device, "_used_subprotocol", False))
    print(f"status_protocol: {'BB 子协议' if uses_bb else '普通 AC 协议'}")
    if uses_bb:
        print(
            "bb_x30_has_elec_query: "
            f"{getattr(device, '_bb_has_electricity_query_30', None)}",
        )
        print(
            "bb_x51_has_elec_query: "
            f"{getattr(device, '_bb_has_electricity_query_51', None)}",
        )
    unsupported = getattr(device, "_unsupported_protocol", [])
    print(
        "unsupported_queries: "
        + (", ".join(unsupported) if unsupported else "无/尚未发现"),
    )

    capabilities = getattr(device, "capabilities", {})
    attributes = device.attributes
    print_capabilities(capabilities)
    print_status_group("通用控制与状态", attributes, GENERAL_STATUS_FIELDS)
    print_status_group("内机观测数据", attributes, INDOOR_STATUS_FIELDS)
    print_status_group("外机观测数据", attributes, OUTDOOR_STATUS_FIELDS)
    print_status_group("能耗与运行时间", attributes, ENERGY_STATUS_FIELDS)

    if show_all:
        print("\n[全部 attributes]")
        for name, value in sorted(attributes.items()):
            print(f"  {name}: {value}")

    print("\n说明：未返回/未知不等于不支持；只有能力声明或有效响应才能确认。")


def print_power_sample(device: Any, current: int, total: int) -> None:  # noqa: ANN401
    """Print fields relevant to one power capture sample."""
    attributes = device.attributes
    values = ", ".join(
        f"{name}={attributes.get(name)!r}" for name in POWER_SAMPLE_FIELDS
    )
    print(f"采样 {current}/{total}: {values}")


def inspect_device(args: argparse.Namespace) -> int:  # noqa: C901
    """Discover, authenticate, and inspect one real AC device."""
    device: Any = None
    try:
        discovered = discover(ip_address=args.host)
        if not discovered:
            print("指定 IP 没有返回局域网发现响应，请检查 IP 和网络。")
            return 1

        info = next(iter(discovered.values()))
        if info["type"] != DeviceType.AC:
            print(f"指定设备不是空调，设备类型为 0x{info['type']:02X}。")
            return 1

        print(
            f"发现设备：device_id={info['device_id']}, model={info['model']}, "
            f"protocol={info['protocol']}, ip={info['ip_address']}:{info['port']}",
        )
        recorder = RawPowerRecorder(args.raw_log)
        device = device_selector(
            name=str(info["device_id"]),
            device_id=info["device_id"],
            device_type=info["type"],
            ip_address=info["ip_address"],
            port=info["port"],
            token=args.token,
            key=args.key,
            device_protocol=info["protocol"],
            model=info["model"],
            subtype=args.subtype,
            customize="",
            mac=info.get("mac"),
            serial_number=info.get("sn"),
        )
        original_process_message = device.process_message
        original_build_send = device.build_send
        original_build_query = device.build_query

        def build_query_with_c1_probes() -> list[Any]:
            """Add read-only C1 and Lua-known BB probes after BB detection."""
            queries: list[Any] = original_build_query()
            if not getattr(device, "_used_subprotocol", False):
                return queries
            protocol_version = queries[0].protocol_version
            if args.bb_status_variants:
                for bb_query_class in (
                    SubProtocolQuery10RunStatus,
                    SubProtocolQuery10RunStatus2,
                    SubProtocolQuery15,
                    SubProtocolQuery4C,
                    SubProtocolQuery51,
                ):
                    if not any(isinstance(query, bb_query_class) for query in queries):
                        queries.append(bb_query_class(protocol_version))
            if args.all_c1_probes:
                for c1_query_class, group in C1_PROBES:
                    enabled = (group != C1_ENERGY_GROUP or args.power_query) and (
                        group != C1_OUTDOOR_POWER_GROUP or args.group_seven
                    )
                    if enabled and not any(
                        isinstance(query, c1_query_class) for query in queries
                    ):
                        queries.append(c1_query_class(protocol_version, padded=True))
            return queries

        def process_message_with_capture(message: bytes) -> dict[str, Any]:
            status: dict[str, Any] = original_process_message(message)
            state = dict(device.attributes)
            state.update(status)
            recorder.record_response(message, state)
            return status

        def build_send_with_capture(command: Any, query: bool = False) -> None:  # noqa: ANN401
            recorder.record_query(
                command.__class__.__name__,
                device.attributes,
                bytes(command.body),
            )
            original_build_send(command, query=query)

        device.process_message = process_message_with_capture
        device.build_send = build_send_with_capture
        device.build_query = build_query_with_c1_probes

        used_bb_before_connect = bool(getattr(device, "_used_subprotocol", False))
        if not device.connect(check_protocol=True):
            print("连接或认证失败，请检查 host、token 和 key。")
            return 1

        switched_to_bb = (
            bool(getattr(device, "_used_subprotocol", False))
            and not used_bb_before_connect
        )
        if switched_to_bb:
            print(
                "检测到 BB 子协议，正在补充标准 C1 与 Lua 已知 BB 只读查询……",
            )
            device.refresh_status(check_protocol=True)

        print(
            f"开始功率/能耗采样：{args.samples} 次，间隔 {args.interval:g} 秒；"
            f"原始日志：{args.raw_log}",
        )
        for sample_index in range(args.samples):
            if sample_index:
                time.sleep(args.interval)
            device.refresh_status(check_protocol=True)
            print_power_sample(device, sample_index + 1, args.samples)

        print_device_report(device, show_all=args.show_all)
        recorder.print_bb_summary()
        recorder.print_x30_changes()
        if str(device.model) == "22396831" and int(device.subtype) == 0:
            recorder.print_x10_total_elec()
            recorder.print_22396831_lua_fields()
        recorder.print_c1_summary()
        attributes = device.attributes
        if (
            attributes.get("compressor_power") is None
            and attributes.get("realtime_power") is None
        ):
            print("\n结论：设备尚未通过已知字段返回功率；不能把频率换算成 W。")
        if all(attributes.get(name) is None for name in ENERGY_STATUS_FIELDS[:4]):
            print("结论：设备尚未通过已知字段返回累计/本次能耗。")
        print(f"完整会话日志：{args.log_file}")
        print(f"解密原始日志：{args.raw_log}")
    except Exception:
        _LOGGER.exception("真实设备检测失败")
        return 1
    else:
        return 0
    finally:
        if device is not None:
            device.close_socket()


def run_with_session_log(args: argparse.Namespace) -> int:
    """Run inspection while mirroring terminal output into a log file."""
    args.log_file.parent.mkdir(parents=True, exist_ok=True)
    with args.log_file.open("a", encoding="utf-8") as log_file:
        tee_stdout = TeeTextStream(sys.stdout, log_file)
        tee_stderr = TeeTextStream(sys.stderr, log_file)
        with (
            contextlib.redirect_stdout(tee_stdout),
            contextlib.redirect_stderr(tee_stderr),
        ):
            logging.basicConfig(
                level=getattr(logging, args.log_level),
                format=(
                    "%(asctime)s.%(msecs)03d %(levelname)s "
                    "(%(threadName)s) [%(name)s] %(message)s"
                ),
                datefmt="%Y-%m-%d %H:%M:%S",
                force=True,
            )
            print("\n" + "=" * 72)
            print(f"session_start={RawPowerRecorder.timestamp()}")
            print(f"host={args.host}, subtype={args.subtype}")
            print("安全提示：会话日志不打印命令行 token/key。")
            result = inspect_device(args)
            print(f"session_end={RawPowerRecorder.timestamp()}, exit_code={result}")
            return result


def main(argv: Sequence[str] | None = None) -> int:
    """Run the real-device AC inspection utility."""
    return run_with_session_log(parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
