from __future__ import annotations

import argparse
import json
import logging
import os
import re
import shutil
import struct
import subprocess
import sys
import zipfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

LOGGER = logging.getLogger("apk_analyzer")
LOGGER.addHandler(logging.NullHandler())

AXML_MAGIC = 0x00080003
CHUNK_STRING_POOL = 0x0001
CHUNK_RESOURCE_IDS = 0x0180
CHUNK_START_NAMESPACE = 0x0100
CHUNK_END_NAMESPACE = 0x0101
CHUNK_START_ELEMENT = 0x0102
CHUNK_END_ELEMENT = 0x0103
CHUNK_CDATA = 0x0104

STRING_POOL_UTF8_FLAG = 0x00000100

TYPE_NULL = 0x00
TYPE_REFERENCE = 0x01
TYPE_STRING = 0x03
TYPE_INT_DEC = 0x10
TYPE_INT_HEX = 0x11
TYPE_INT_BOOLEAN = 0x12

ATTR_PACKAGE = "package"
ATTR_VERSION_CODE = "versionCode"
ATTR_VERSION_NAME = "versionName"
ATTR_COMPILE_SDK = "compileSdkVersion"
ATTR_PLATFORM_BUILD_SDK = "platformBuildVersionCode"
ATTR_PLATFORM_BUILD_CODENAME = "platformBuildVersionName"
ATTR_MIN_SDK = "minSdkVersion"
ATTR_TARGET_SDK = "targetSdkVersion"
ATTR_NAME = "name"
ATTR_LABEL = "label"

MANIFEST_NAME = "AndroidManifest.xml"
LIB_PREFIX = "lib/"
DEX_PATTERN = re.compile(r"^classes(?:\d+)?\.dex$")

_ARCH_ALIASES = {
    "arm64-v8a": "arm64-v8a",
    "armeabi-v7a": "armeabi-v7a",
    "armeabi": "armeabi",
    "x86": "x86",
    "x86_64": "x86_64",
    "mips": "mips",
    "mips64": "mips64",
    "riscv64": "riscv64",
}


class ApkAnalysisError(Exception):
    pass


class AxmlParseError(ApkAnalysisError):
    pass


@dataclass
class AxmlStringPool:
    strings: List[str] = field(default_factory=list)
    utf8: bool = False


@dataclass
class ApkReport:
    path: str
    size_bytes: int
    sha256: str
    is_zip: bool
    is_apk: bool
    abis: List[str] = field(default_factory=list)
    dex_files: List[str] = field(default_factory=list)
    dex_count: int = 0
    has_manifest: bool = False
    package: Optional[str] = None
    version_code: Optional[int] = None
    version_name: Optional[str] = None
    min_sdk: Optional[int] = None
    target_sdk: Optional[int] = None
    compile_sdk: Optional[int] = None
    permissions: List[str] = field(default_factory=list)
    declared_features: List[str] = field(default_factory=list)
    application_label: Optional[str] = None
    native_libs: Dict[str, List[str]] = field(default_factory=dict)
    total_native_libs: int = 0
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


def _safe_read(path: Path, limit: Optional[int] = None) -> bytes:
    if not path.exists():
        raise ApkAnalysisError(f"Fichier introuvable : {path}")
    if not path.is_file():
        raise ApkAnalysisError(f"Chemin non régulier : {path}")
    size = path.stat().st_size
    if size == 0:
        raise ApkAnalysisError(f"Fichier vide : {path}")
    if limit is not None and size > limit:
        raise ApkAnalysisError(
            f"Fichier trop volumineux ({size} octets > {limit})"
        )
    with path.open("rb") as fh:
        return fh.read()


def _decode_string_pool(data: bytes, offset: int) -> Tuple[AxmlStringPool, int]:
    if offset + 8 > len(data):
        raise AxmlParseError("Troncature de l'en-tête du pool de chaînes")
    chunk_type, header_size, chunk_size = struct.unpack_from("<HHI", data, offset)
    if chunk_type != CHUNK_STRING_POOL:
        raise AxmlParseError(
            f"Chunk attendu STRING_POOL, obtenu 0x{chunk_type:04x}"
        )
    if chunk_size < header_size or offset + chunk_size > len(data):
        raise AxmlParseError("Taille de chunk invalide pour STRING_POOL")

    string_count, style_count, flags, strings_start, styles_start = struct.unpack_from(
        "<IIIII", data, offset + 8
    )
    utf8 = bool(flags & STRING_POOL_UTF8_FLAG)

    offsets_end = offset + header_size
    if offsets_end + string_count * 4 > len(data):
        raise AxmlParseError("Table d'offsets tronquée")
    offsets = struct.unpack_from(f"<{string_count}I", data, offsets_end)

    pool = AxmlStringPool(utf8=utf8)
    strings_base = offset + strings_start
    for idx in range(string_count):
        str_off = strings_base + offsets[idx]
        if str_off >= len(data):
            pool.strings.append("")
            continue
        try:
            value = _read_pool_string(data, str_off, utf8)
        except (IndexError, struct.error):
            value = ""
        pool.strings.append(value)

    return pool, chunk_size


def _read_length(data: bytes, pos: int, utf8: bool) -> Tuple[int, int]:
    if utf8:
        if pos >= len(data):
            raise IndexError("Offset hors limites (UTF-8 len)")
        b0 = data[pos]
        if b0 & 0x80:
            b1 = data[pos + 1]
            return ((b0 & 0x7F) << 8) | b1, 2
        return b0, 1
    v = struct.unpack_from("<H", data, pos)[0]
    if v & 0x8000:
        v2 = struct.unpack_from("<H", data, pos + 2)[0]
        return ((v & 0x7FFF) << 16) | v2, 4
    return v, 2


def _read_pool_string(data: bytes, pos: int, utf8: bool) -> str:
    if utf8:
        _char_len, n1 = _read_length(data, pos, True)
        byte_len, n2 = _read_length(data, pos + n1, True)
        start = pos + n1 + n2
        raw = data[start:start + byte_len]
        return raw.decode("utf-8", errors="replace")
    char_len, n = _read_length(data, pos, False)
    start = pos + n
    raw = data[start:start + char_len * 2]
    return raw.decode("utf-16-le", errors="replace")


def _typed_value_to_python(
    data: bytes, offset: int, pool: AxmlStringPool
) -> Any:
    if offset + 8 > len(data):
        return None
    size, res0, data_type, value = struct.unpack_from("<HBBI", data, offset)
    if size < 8:
        return None
    if data_type == TYPE_NULL:
        return None
    if data_type == TYPE_STRING:
        if 0 <= value < len(pool.strings):
            return pool.strings[value]
        return None
    if data_type == TYPE_REFERENCE:
        return value
    if data_type == TYPE_INT_DEC or data_type == TYPE_INT_HEX:
        return value
    if data_type == TYPE_INT_BOOLEAN:
        return bool(value)
    return value


def _parse_axml(data: bytes) -> Dict[str, Any]:
    if len(data) < 8:
        raise AxmlParseError("Fichier AXML trop court")
    magic, _file_size = struct.unpack_from("<II", data, 0)
    if magic != AXML_MAGIC:
        raise AxmlParseError(f"Magic AXML invalide : 0x{magic:08x}")

    strings_pool: Optional[AxmlStringPool] = None
    result: Dict[str, Any] = {
        "package": None,
        "version_code": None,
        "version_name": None,
        "min_sdk": None,
        "target_sdk": None,
        "compile_sdk": None,
        "permissions": [],
        "features": [],
        "label": None,
    }

    pos = 8
    while pos + 8 <= len(data):
        chunk_type, header_size, chunk_size = struct.unpack_from("<HHI", data, pos)
        if chunk_size == 0 or pos + chunk_size > len(data):
            break

        if chunk_type == CHUNK_STRING_POOL:
            try:
                strings_pool, _ = _decode_string_pool(data, pos)
            except AxmlParseError:
                strings_pool = None

        elif chunk_type == CHUNK_START_ELEMENT and strings_pool is not None:
            try:
                _process_start_element(data, pos, strings_pool, result)
            except (struct.error, IndexError):
                pass

        pos += chunk_size

    return result


def _process_start_element(
    data: bytes,
    offset: int,
    pool: AxmlStringPool,
    result: Dict[str, Any],
) -> None:
    header_size = struct.unpack_from("<H", data, offset + 2)[0]
    body = offset + header_size

    _line, _comment, ns_idx, name_idx, attr_start, attr_size, attr_count, _i, _c, _s = struct.unpack_from(
        "<IIIIHHHHHH", data, body
    )

    if name_idx >= len(pool.strings):
        return
    element_name = pool.strings[name_idx]

    attrs_base = body + attr_start
    collected: Dict[str, Any] = {}
    for i in range(attr_count):
        a_off = attrs_base + i * attr_size
        if a_off + attr_size > len(data):
            break
        ns_a, name_a, raw_idx = struct.unpack_from("<III", data, a_off)
        attr_name = (
            pool.strings[name_a] if name_a < len(pool.strings) else ""
        )
        typed_off = a_off + 12
        value = _typed_value_to_python(data, typed_off, pool)
        if value is None and raw_idx != 0xFFFFFFFF and raw_idx < len(pool.strings):
            value = pool.strings[raw_idx]
        collected[attr_name] = value

    if element_name == "manifest":
        result["package"] = collected.get(ATTR_PACKAGE) or result["package"]
        vc = collected.get(ATTR_VERSION_CODE)
        if vc is None:
            vc = collected.get(ATTR_PLATFORM_BUILD_SDK)
        result["version_code"] = _as_int(vc) or result["version_code"]
        vn = collected.get(ATTR_VERSION_NAME)
        if vn is None:
            vn = collected.get(ATTR_PLATFORM_BUILD_CODENAME)
        if vn:
            result["version_name"] = str(vn)
        cs = collected.get(ATTR_COMPILE_SDK)
        result["compile_sdk"] = _as_int(cs) or result["compile_sdk"]

    elif element_name == "uses-sdk":
        ms = collected.get(ATTR_MIN_SDK)
        ts = collected.get(ATTR_TARGET_SDK)
        if ms is not None:
            result["min_sdk"] = _as_int(ms)
        if ts is not None:
            result["target_sdk"] = _as_int(ts)

    elif element_name == "uses-permission":
        perm = collected.get(ATTR_NAME)
        if perm:
            result["permissions"].append(str(perm))

    elif element_name == "uses-feature":
        feat = collected.get(ATTR_NAME)
        if feat:
            result["features"].append(str(feat))

    elif element_name == "application":
        label = collected.get(ATTR_LABEL)
        if isinstance(label, str):
            result["label"] = label


def _as_int(value: Any) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError:
            return None
    return None


def _analyze_zip(apk_path: Path, report: ApkReport) -> None:
    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            names = zf.namelist()
    except zipfile.BadZipFile:
        raise ApkAnalysisError("Archive ZIP invalide")
    except OSError as exc:
        raise ApkAnalysisError(f"Erreur d'accès au ZIP : {exc}") from exc

    abis = set()
    native_libs: Dict[str, List[str]] = {}
    dex_files: List[str] = []
    has_manifest = False

    for name in names:
        if name == MANIFEST_NAME:
            has_manifest = True
        if LIB_PREFIX in name and name.startswith(LIB_PREFIX):
            parts = name.split("/")
            if len(parts) >= 3 and parts[2]:
                abi = parts[1]
                canonical = _ARCH_ALIASES.get(abi, abi)
                abis.add(canonical)
                native_libs.setdefault(canonical, []).append(parts[-1])
        base = name.rsplit("/", 1)[-1]
        if DEX_PATTERN.match(base):
            dex_files.append(base)

    report.abis = sorted(abis)
    report.native_libs = {k: sorted(v) for k, v in native_libs.items()}
    report.total_native_libs = sum(len(v) for v in native_libs.values())
    report.dex_files = sorted(dex_files)
    report.dex_count = len(dex_files)
    report.has_manifest = has_manifest
    report.is_apk = has_manifest and report.dex_count > 0


def _read_manifest_bytes(apk_path: Path) -> Optional[bytes]:
    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            if MANIFEST_NAME not in zf.namelist():
                return None
            info = zf.getinfo(MANIFEST_NAME)
            if info.file_size > 16 * 1024 * 1024:
                LOGGER.warning("AndroidManifest.xml anormalement volumineux")
                return None
            return zf.read(MANIFEST_NAME)
    except (zipfile.BadZipFile, KeyError, OSError) as exc:
        LOGGER.warning("Lecture AndroidManifest.xml impossible : %s", exc)
        return None


def _run_external_tool(apk_path: Path) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    tool = shutil.which("aapt2") or shutil.which("aapt")
    if tool is None:
        return result

    try:
        proc = subprocess.run(
            [tool, "dump", "badging", str(apk_path)],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        LOGGER.warning("Échec d'exécution de %s : %s", tool, exc)
        return result

    if proc.returncode != 0:
        LOGGER.warning(
            "%s a retourné un code %s", tool, proc.returncode
        )
        return result

    for line in proc.stdout.splitlines():
        if line.startswith("package:"):
            m = re.search(r"name='([^']+)'", line)
            if m:
                result.setdefault("package", m.group(1))
            m = re.search(r"versionCode='([^']+)'", line)
            if m:
                result.setdefault("version_code", _as_int(m.group(1)))
            m = re.search(r"versionName='([^']+)'", line)
            if m:
                result.setdefault("version_name", m.group(1))
        elif line.startswith("sdkVersion:"):
            result.setdefault("min_sdk", _as_int(line.split(":", 1)[1].strip()))
        elif line.startswith("targetSdkVersion:"):
            result.setdefault(
                "target_sdk", _as_int(line.split(":", 1)[1].strip())
            )
        elif line.startswith("application-label:"):
            m = re.search(r"'([^']+)'", line)
            if m:
                result.setdefault("label", m.group(1))
        elif line.startswith("uses-permission:"):
            m = re.search(r"name='([^']+)'", line)
            if m:
                result.setdefault("permissions", []).append(m.group(1))
        elif line.startswith("native-code:"):
            m = re.findall(r"'([^']+)'", line)
            if m:
                result.setdefault("abis", []).extend(m)

    return result


def _sha256(path: Path) -> str:
    import hashlib

    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def analyze_apk(apk_path: Path) -> ApkReport:
    if not isinstance(apk_path, Path):
        apk_path = Path(apk_path)

    if not apk_path.exists():
        raise ApkAnalysisError(f"Fichier introuvable : {apk_path}")

    size = apk_path.stat().st_size
    if size < 1024:
        raise ApkAnalysisError(
            f"Fichier trop petit pour être un APK valide : {size} octets"
        )

    report = ApkReport(
        path=str(apk_path),
        size_bytes=size,
        sha256=_sha256(apk_path),
        is_zip=False,
        is_apk=False,
    )

    try:
        _analyze_zip(apk_path, report)
        report.is_zip = True
    except ApkAnalysisError as exc:
        report.errors.append(str(exc))
        return report

    manifest_bytes = _read_manifest_bytes(apk_path)
    if manifest_bytes is None:
        report.warnings.append("AndroidManifest.xml introuvable dans l'APK")
    else:
        try:
            parsed = _parse_axml(manifest_bytes)
            report.package = parsed.get("package") or report.package
            report.version_code = parsed.get("version_code") or report.version_code
            report.version_name = parsed.get("version_name") or report.version_name
            report.min_sdk = parsed.get("min_sdk") or report.min_sdk
            report.target_sdk = parsed.get("target_sdk") or report.target_sdk
            report.compile_sdk = parsed.get("compile_sdk") or report.compile_sdk
            if parsed.get("permissions"):
                report.permissions = sorted(set(parsed["permissions"]))
            if parsed.get("features"):
                report.declared_features = sorted(set(parsed["features"]))
            if parsed.get("label"):
                report.application_label = str(parsed["label"])
        except AxmlParseError as exc:
            report.warnings.append(f"Échec d'analyse AXML : {exc}")

    external = _run_external_tool(apk_path)
    if external:
        if not report.package and external.get("package"):
            report.package = external["package"]
        if report.version_code is None and external.get("version_code") is not None:
            report.version_code = external["version_code"]
        if not report.version_name and external.get("version_name"):
            report.version_name = external["version_name"]
        if report.min_sdk is None and external.get("min_sdk") is not None:
            report.min_sdk = external["min_sdk"]
        if report.target_sdk is None and external.get("target_sdk") is not None:
            report.target_sdk = external["target_sdk"]
        if not report.application_label and external.get("label"):
            report.application_label = external["label"]
        if external.get("permissions") and not report.permissions:
            report.permissions = sorted(set(external["permissions"]))
        if external.get("abis"):
            merged = set(report.abis) | set(external["abis"])
            report.abis = sorted(merged)

    if not report.abis:
        report.warnings.append("Aucune bibliothèque native détectée (APK pur Java/Kotlin possible)")

    if report.min_sdk is None:
        report.warnings.append("minSdkVersion non détecté")

    if report.target_sdk is None:
        report.warnings.append("targetSdkVersion non détecté")

    return report


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="apk_analyzer",
        description="Analyse un fichier APK et retourne un rapport JSON.",
    )
    parser.add_argument(
        "apk",
        type=Path,
        help="Chemin vers le fichier APK à analyser",
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Affiche le JSON avec indentation",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Chemin d'écriture optionnel du rapport JSON",
    )
    parser.add_argument(
        "--fail-on-error",
        action="store_true",
        help="Retourne un code non nul si une erreur bloquante est détectée",
    )
    parser.add_argument(
        "--log-level",
        default="WARNING",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Niveau de journalisation",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

    try:
        report = analyze_apk(args.apk)
    except ApkAnalysisError as exc:
        LOGGER.error("Analyse échouée : %s", exc)
        sys.stderr.write(f"apk_analyzer: {exc}\n")
        return 2
    except Exception:
        LOGGER.exception("Erreur inattendue lors de l'analyse")
        sys.stderr.write("apk_analyzer: erreur inattendue\n")
        return 3

    payload = asdict(report)
    indent = 2 if args.pretty else None
    serialized = json.dumps(payload, indent=indent, ensure_ascii=False)

    if args.output is not None:
        try:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            tmp = args.output.with_suffix(args.output.suffix + ".tmp")
            with tmp.open("w", encoding="utf-8") as fh:
                fh.write(serialized)
                fh.write("\n")
            os.replace(tmp, args.output)
        except OSError as exc:
            LOGGER.error("Écriture du rapport impossible : %s", exc)
            sys.stderr.write(f"apk_analyzer: écriture impossible : {exc}\n")
            return 4

    sys.stdout.write(serialized)
    sys.stdout.write("\n")

    if args.fail_on_error and report.errors:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
