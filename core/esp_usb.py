"""USB/serial ESP8266 detection, Arduino sketch compilation, and firmware flashing."""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
import tempfile
import threading
from pathlib import Path
from typing import Any

try:
    from serial.tools import list_ports
    SERIAL_AVAILABLE = True
except ImportError:
    SERIAL_AVAILABLE = False


MAX_FIRMWARE_SIZE = 16 * 1024 * 1024
MAX_SKETCH_SIZE = 2 * 1024 * 1024
DEFAULT_BAUD = 460800
DEFAULT_FQBN = "esp8266:esp8266:nodemcuv2"
ALLOWED_FQBNS = {
    "esp8266:esp8266:nodemcuv2",
    "esp8266:esp8266:d1_mini",
    "esp8266:esp8266:generic",
}

ESP_HINTS = (
    "esp8266", "nodemcu", "wemos", "ch340", "ch341", "cp210",
    "silicon labs", "qin heng", "usb-serial", "usb serial", "ft232",
)


class EspUsbManager:
    """Detect host serial ports and flash an ESP8266 firmware image."""

    def __init__(self) -> None:
        self.last_flash: dict[str, Any] | None = None
        self._flash_lock = threading.Lock()

    @staticmethod
    def _is_probably_esp(info: Any) -> bool:
        haystack = " ".join(
            str(value or "")
            for value in (
                getattr(info, "device", ""), getattr(info, "description", ""),
                getattr(info, "manufacturer", ""), getattr(info, "product", ""),
                getattr(info, "hwid", ""),
            )
        ).lower()
        if any(hint in haystack for hint in ESP_HINTS):
            return True
        known_usb_ids = (
            "1a86:7523", "1a86:5523", "1a86:55d4",
            "10c4:ea60", "0403:6001", "0403:6010",
        )
        return any(usb_id in haystack for usb_id in known_usb_ids)

    def list_devices(self) -> dict[str, Any]:
        capabilities = {
            "pyserial": SERIAL_AVAILABLE,
            "esptool": shutil.which("esptool") is not None or self._module_available("esptool"),
            "arduino_cli": shutil.which("arduino-cli") is not None,
        }
        if not SERIAL_AVAILABLE:
            return {
                "available": False,
                "message": "pyserial belum terpasang",
                "devices": [],
                "capabilities": capabilities,
            }

        devices = []
        for info in sorted(list_ports.comports(), key=lambda p: p.device):
            devices.append({
                "port": info.device,
                "name": info.name or info.device,
                "description": info.description or "Unknown serial device",
                "manufacturer": getattr(info, "manufacturer", None),
                "product": getattr(info, "product", None),
                "serial_number": getattr(info, "serial_number", None),
                "vid": getattr(info, "vid", None),
                "pid": getattr(info, "pid", None),
                "hwid": getattr(info, "hwid", None),
                "likely_esp8266": self._is_probably_esp(info),
            })
        return {
            "available": True,
            "message": f"{len(devices)} serial device terdeteksi",
            "devices": devices,
            "capabilities": capabilities,
        }

    @staticmethod
    def _module_available(name: str) -> bool:
        try:
            proc = subprocess.run(
                [sys.executable, "-c", f"import {name}"],
                capture_output=True, timeout=5,
            )
            return proc.returncode == 0
        except Exception:
            return False

    def _allowed_port(self, port: str) -> bool:
        if not SERIAL_AVAILABLE or not port:
            return False
        return any(item.get("port") == port for item in self.list_devices()["devices"])

    @staticmethod
    def _resolve_esptool_command(port: str, baud: int, address: str, firmware: str) -> list[str]:
        base = [
            sys.executable, "-m", "esptool",
            "--chip", "esp8266",
            "--port", port,
            "--baud", str(baud),
        ]
        help_result = subprocess.run(
            [sys.executable, "-m", "esptool", "--help"],
            capture_output=True, text=True, timeout=15,
        )
        help_text = (help_result.stdout or "") + "\n" + (help_result.stderr or "")
        subcommand = "write-flash" if "write-flash" in help_text else "write_flash"
        return base + [subcommand, address, firmware]

    def _compile_ino(self, sketch_path: Path, fqbn: str) -> tuple[Path | None, str, tempfile.TemporaryDirectory | None]:
        """Compile a single-file Arduino sketch and return the produced .bin path."""
        if shutil.which("arduino-cli") is None:
            return None, (
                "File .ino perlu dikompile terlebih dahulu, tetapi arduino-cli tidak ditemukan. "
                "Install Arduino CLI + ESP8266 core, atau upload file .bin hasil compile."
            ), None
        if fqbn not in ALLOWED_FQBNS:
            return None, "Profil board/FQBN tidak didukung.", None

        work = tempfile.TemporaryDirectory(prefix="wifi_monitor_ino_")
        work_path = Path(work.name)
        sketch_dir = work_path / "firmware"
        output_dir = work_path / "build"
        sketch_dir.mkdir(parents=True, exist_ok=True)
        output_dir.mkdir(parents=True, exist_ok=True)
        target_sketch = sketch_dir / "firmware.ino"
        shutil.copy2(sketch_path, target_sketch)

        command = [
            "arduino-cli", "compile",
            "--fqbn", fqbn,
            "--output-dir", str(output_dir),
            str(sketch_dir),
        ]
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=180)
        except subprocess.TimeoutExpired:
            work.cleanup()
            return None, "Compile .ino timeout setelah 180 detik.", None
        except Exception as exc:
            work.cleanup()
            return None, f"Gagal menjalankan arduino-cli: {exc}", None

        log = ((result.stdout or "") + "\n" + (result.stderr or "")).strip()
        if result.returncode != 0:
            work.cleanup()
            return None, "Compile .ino gagal.\n\n" + log[-12000:], None

        bins = sorted(output_dir.glob("*.bin"), key=lambda p: p.stat().st_size, reverse=True)
        # Prefer the normal application image, not filesystem/bootloader variants.
        preferred = [p for p in bins if not any(x in p.name.lower() for x in ("littlefs", "spiffs", "bootloader"))]
        chosen = (preferred or bins)[0] if (preferred or bins) else None
        if chosen is None:
            work.cleanup()
            return None, "Compile selesai tetapi file .bin hasil build tidak ditemukan.", None
        return chosen, log[-8000:], work

    def flash(
        self,
        port: str,
        firmware_path: str,
        *,
        original_name: str | None = None,
        baud: int = DEFAULT_BAUD,
        address: str = "0x0000",
        fqbn: str = DEFAULT_FQBN,
    ) -> dict[str, Any]:
        port = (port or "").strip()
        address = (address or "0x0000").strip()
        source = Path(firmware_path)
        display_name = original_name or source.name
        source_ext = Path(display_name).suffix.lower()

        if not port:
            return {"success": False, "message": "Pilih COM/serial port ESP terlebih dahulu."}
        if not self._allowed_port(port):
            return {"success": False, "message": f"Port serial {port} tidak terdeteksi. Refresh lalu pilih port yang tersedia."}
        if not source.is_file():
            return {"success": False, "message": "File firmware tidak ditemukan."}
        if source_ext not in {".bin", ".ino"}:
            return {"success": False, "message": "Firmware harus berupa file .bin atau .ino."}
        if source.stat().st_size <= 0:
            return {"success": False, "message": "File firmware kosong."}
        size_limit = MAX_SKETCH_SIZE if source_ext == ".ino" else MAX_FIRMWARE_SIZE
        if source.stat().st_size > size_limit:
            return {"success": False, "message": "File firmware terlalu besar."}
        if not re.fullmatch(r"0x[0-9a-fA-F]+|[0-9]+", address):
            return {"success": False, "message": "Alamat flash tidak valid. Contoh: 0x0000"}

        if not self._flash_lock.acquire(blocking=False):
            return {"success": False, "message": "Sedang ada proses flash ESP lain. Tunggu sampai selesai."}

        compile_log = ""
        compile_work = None
        flash_path = source
        try:
            if source_ext == ".ino":
                flash_path, compile_log, compile_work = self._compile_ino(source, fqbn)
                if flash_path is None:
                    return {"success": False, "message": compile_log, "stage": "compile"}

            try:
                command = self._resolve_esptool_command(port, int(baud), address, str(flash_path))
            except Exception as exc:
                return {"success": False, "message": f"Gagal menyiapkan esptool: {exc}", "stage": "prepare"}

            try:
                result = subprocess.run(command, capture_output=True, text=True, timeout=180)
            except subprocess.TimeoutExpired:
                return {"success": False, "message": "Upload timeout setelah 180 detik.", "stage": "flash"}
            except Exception as exc:
                return {"success": False, "message": f"Gagal menjalankan esptool: {exc}", "stage": "flash"}

            flash_log = ((result.stdout or "") + "\n" + (result.stderr or "")).strip()
            success = result.returncode == 0
            combined_log = ""
            if compile_log:
                combined_log += "[COMPILE]\n" + compile_log + "\n\n"
            combined_log += "[FLASH]\n" + flash_log

            response = {
                "success": success,
                "message": "Firmware berhasil di-flash ke ESP8266." if success else "Flash firmware gagal.",
                "stage": "done" if success else "flash",
                "port": port,
                "address": address,
                "baud": int(baud),
                "filename": display_name,
                "source_type": source_ext.lstrip("."),
                "fqbn": fqbn if source_ext == ".ino" else None,
                "size": source.stat().st_size,
                "returncode": result.returncode,
                "log": combined_log[-16000:],
            }
            self.last_flash = response
            return response
        finally:
            if compile_work is not None:
                compile_work.cleanup()
            self._flash_lock.release()


esp_usb_manager = EspUsbManager()
