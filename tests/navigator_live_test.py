"""Read-only live probe for Midea AC BB 0x10 Navigator telemetry."""

# ruff: noqa: T201

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from midealan.const import DeviceType
from midealan.device import MideaDevice
from midealan.devices import device_selector
from midealan.discover import discover


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("ip", help="Indoor unit IP address")
    parser.add_argument("--token", required=True, help="Device token as hex")
    parser.add_argument("--key", required=True, help="Device key as hex")
    parser.add_argument("--samples", type=int, default=6)
    parser.add_argument("--interval", type=float, default=10.0)
    return parser.parse_args()


def all_attributes(device: MideaDevice) -> dict[str, object]:
    """Return every available attribute, omitting null values."""
    return {
        attribute: value
        for attribute, value in sorted(device.attributes.items())
        if value is not None
    }


def main() -> None:
    """Discover, authenticate, and query an indoor unit without controls."""
    args = parse_args()
    found = discover(ip_address=args.ip)
    if not found:
        raise SystemExit(f"No Midea device discovered at {args.ip}")
    info = next(iter(found.values()))
    if info["type"] != DeviceType.AC:
        raise SystemExit(f"Device is type 0x{info['type']:02x}, not AC (0xac)")

    device = device_selector(
        name="Navigator live probe",
        device_id=info["device_id"],
        device_type=info["type"],
        ip_address=info["ip_address"],
        port=info["port"],
        token=args.token,
        key=args.key,
        device_protocol=info["protocol"],
        model=info["model"],
        subtype=0,
        customize="",
        mac=info["mac"],
        serial_number=info["sn"],
    )
    if not device.connect(check_protocol=True):
        raise SystemExit("Connection/authentication failed")

    try:
        print(
            json.dumps(
                {
                    "device_id": str(info["device_id"]),
                    "model": info["model"],
                    "ip": info["ip_address"],
                },
                ensure_ascii=False,
            ),
        )
        for sample in range(1, args.samples + 1):
            if sample > 1:
                device.refresh_status(check_protocol=True)
            print(
                json.dumps(
                    {
                        "sample": sample,
                        "time": time.strftime("%Y-%m-%d %H:%M:%S"),
                        **all_attributes(device),
                    },
                    ensure_ascii=False,
                ),
                flush=True,
            )
            if sample < args.samples:
                time.sleep(args.interval)
    finally:
        device.close_socket()


if __name__ == "__main__":
    main()
