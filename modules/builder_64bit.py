from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import re
import struct
import sys
import time
import zipfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

LOGGER = logging.getLogger("builder_64bit")
LOGGER.addHandler(logging.NullHandler())

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_INPUT_DIR = PROJECT_ROOT / "data" / "input"
DEFAULT_OUTPUT_DIR = PROJECT_ROOT / "data" / "output"
DEFAULT_LOG_DIR = PROJECT_ROOT / "data" / "logs"

SUPPORTED_ARCHITECTURES: Tuple[str, ...] = (
    "arm64-v8a",
    "armeabi-v7a",
    "armeabi",
    "x86",
    "x86_64",
    "mips",
    "mips64",
    "riscv64",
)

SIXTY_FOUR_BIT_ARCHS: Tuple[str, ...] = (
    "arm64-v8a",
    "x86_64",
    "mips64",
    "riscv64",
)

THIRTY_TWO_BIT_ARCHS: Tuple[str, ...] = (
    "armeabi-v7a",
    "armeabi",
    "x86",
    "mips",
)

LIB_PREFIX = "lib/"
SO_SUFFIX = ".so"
ALIGNMENT = 4
PADDING_EXTRA_ID = 0xD935
MIN_APK_SIZE = 1024
MAX_APK_SIZE = 8 * 1024 * 1024 * 1024
REQUIRED_ENTRIES: Tuple[str, ...] = ("AndroidManifest.xml",)
DEX_PATTERN = re.compile(r"^classes(?:\d+)?\.dex$")

UNCOMPRESSED_EXTENSIONS: Tuple[str, ...] = (
    ".so",
    ".arsc",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".mp3",
    ".mp4",
    ".ogg",
    ".wav",
    ".m4a",
    ".ttf",
    ".otf",
    ".woff",
    ".woff2",
)

class BuilderError(Exception):
    pass

class ValidationError(BuilderError):
    pass

class RepackError(BuilderError):
    pass

@dataclass
class BuildReport:
    input_path: str
    output_path: str
    input_size: int
    output_size: int
    input_sha256: str
    output_sha256: str
    target_architectures: List[str] = field(default_factory=list)
    detected_architectures: List[str] = field(default_factory=list)
    kept_architectures: List[str] = field(default_factory=list)
    removed_architectures: List[str] = field(default_factory=list)
    total_entries: int = 0
    kept_entries: int = 0
    removed_entries: int = 0
    kept_native_libs: int = 0
    removed_native_libs: int = 0
    removed_native_lib_names: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    duration_seconds: float = 0.0
    output_verified: bool = False

def _sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(chunk_size), b""):
            h.update(chunk)
    return h.hexdigest()

def _normalize_architecture(arch: str) -> str:
    if not isinstance(arch, str):
        raise ValidationError("L'architecture doit être une chaîne")
    normalized = arch.strip().lower()
    if normalized not in SUPPORTED_ARCHITECTURES:
        raise ValidationError(
            f"Architecture non supportée : {arch!r}. "
            f"Valeurs autorisées : {', '.join(SUPPORTED_ARCHITECTURES)}"
        )
    return normalized

def _validate_input(apk_path: Path) -> None:
    if not apk_path.exists():
        raise ValidationError(f"APK introuvable : {apk_path}")
    if not apk_path.is_file():
        raise ValidationError(f"Chemin non régulier : {apk_path}")
    size = apk_path.stat().st_size
    if size < MIN_APK_SIZE:
        raise ValidationError(f"APK trop petit ({size} octets)")
    if size > MAX_APK_SIZE:
        raise ValidationError(f"APK trop volumineux ({size} octets)")
    try:
        with apk_path.open("rb") as fh:
            magic = fh.read(2)
    except OSError as exc:
        raise ValidationError(f"Lecture de l'APK impossible : {exc}") from exc
    if magic != b"PK":
        raise ValidationError(
            f"Le fichier {apk_path} n'est pas une archive ZIP/APK valide"
        )

def _is_native_lib_entry(name: str) -> bool:
    if not name.startswith(LIB_PREFIX):
        return False
    parts = name.split("/")
    if len(parts) < 3:
        return False
    if not parts[2]:
        return False
    return parts[-1].endswith(SO_SUFFIX)

def _extract_arch_from_entry(name: str) -> Optional[str]:
    if not name.startswith(LIB_PREFIX):
        return None
    parts = name.split("/")
    if len(parts) < 3:
        return None
    abi = parts[1]
    if abi not in SUPPORTED_ARCHITECTURES:
        return None
    return abi

def _should_store_uncompressed(name: str) -> bool:
    lower = name.lower()
    for ext in UNCOMPRESSED_EXTENSIONS:
        if lower.endswith(ext):
            return True
    return False

def _write_aligned_entry(
    zf_out: zipfile.ZipFile,
    zi: zipfile.ZipInfo,
    data: bytes,
    alignment: int = ALIGNMENT,
) -> None:
    if zi.compress_type != zipfile.ZIP_STORED or zf_out.fp is None:
        zf_out.writestr(zi, data)
        return

    try:
        current = zf_out.fp.tell()
    except (OSError, AttributeError, ValueError):
        zf_out.writestr(zi, data)
        return

    filename_bytes = zi.filename.encode("utf-8")
    header_size = 30 + len(filename_bytes)
    base = current + header_size
    extra_len = (-base) % alignment
    while 0 < extra_len < 4:
        extra_len += alignment

    if extra_len == 0:
        zi.extra = b""
    else:
        payload_len = extra_len - 4
        zi.extra = struct.pack("<HH", PADDING_EXTRA_ID, payload_len) + (
            b"\x00" * payload_len
        )

    zf_out.writestr(zi, data)

def _build_zipinfo(
    source_info: zipfile.ZipInfo,
    use_stored: bool,
) -> zipfile.ZipInfo:
    zi = zipfile.ZipInfo(
        filename=source_info.filename,
        date_time=source_info.date_time,
    )
    if use_stored or source_info.compress_type == zipfile.ZIP_STORED:
        zi.compress_type = zipfile.ZIP_STORED
    else:
        zi.compress_type = zipfile.ZIP_DEFLATED
    zi.external_attr = source_info.external_attr
    zi.internal_attr = source_info.internal_attr
    zi.create_system = 3
    zi.create_version = 20
    zi.extract_version = 20
    zi.flag_bits = 0
    return zi

def _verify_output(
    apk_path: Path,
    allowed_architectures: Sequence[str],
) -> Tuple[bool, List[str], List[str]]:
    warnings: List[str] = []
    errors: List[str] = []

    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            bad = zf.testzip()
            if bad is not None:
                errors.append(f"Entrée corrompue détectée : {bad}")
            names = set(zf.namelist())
    except zipfile.BadZipFile as exc:
        errors.append(f"APK de sortie invalide : {exc}")
        return False, warnings, errors
    except OSError as exc:
        errors.append(f"Lecture impossible de l'APK de sortie : {exc}")
        return False, warnings, errors

    for required in REQUIRED_ENTRIES:
        if required not in names:
            errors.append(f"Entrée obligatoire manquante : {required}")

    if not any(DEX_PATTERN.match(n.rsplit("/", 1)[-1]) for n in names):
        errors.append("Aucun fichier classes*.dex trouvé dans l'APK de sortie")

    allowed = set(allowed_architectures)
    for name in names:
        arch = _extract_arch_from_entry(name)
        if arch is not None and arch not in allowed:
            errors.append(
                f"Bibliothèque native résiduelle détectée : {name}"
            )

    if "META-INF/MANIFEST.MF" in names or "META-INF/CERT.RSA" in names:
        warnings.append(
            "Signature résiduelle détectée dans META-INF ; "
            "une re-signature est nécessaire"
        )

    return len(errors) == 0, warnings, errors

def build_64bit_apk(
    input_apk: Path,
    output_apk: Path,
    target_architectures: Optional[Sequence[str]] = None,
    keep_all_64bit: bool = True,
) -> BuildReport:
    if not isinstance(input_apk, Path):
        input_apk = Path(input_apk)
    if not isinstance(output_apk, Path):
        output_apk = Path(output_apk)

    _validate_input(input_apk)

    if input_apk.resolve() == output_apk.resolve():
        raise ValidationError(
            "Le chemin de sortie doit être différent du chemin d'entrée"
        )

    normalized_targets: List[str]
    if target_architectures is None:
        normalized_targets = []
    else:
        normalized_targets = [
            _normalize_architecture(a) for a in target_architectures
        ]

    if not normalized_targets:
        if keep_all_64bit:
            normalized_targets = list(SIXTY_FOUR_BIT_ARCHS)
        else:
            raise ValidationError(
                "Aucune architecture cible spécifiée et keep_all_64bit est désactivé"
            )

    for arch in normalized_targets:
        if arch not in SIXTY_FOUR_BIT_ARCHS:
            raise ValidationError(
                f"L'architecture cible {arch!r} n'est pas 64-bit"
            )

    target_set = set(normalized_targets)

    report = BuildReport(
        input_path=str(input_apk),
        output_path=str(output_apk),
        input_size=input_apk.stat().st_size,
        output_size=0,
        input_sha256="",
        output_sha256="",
        target_architectures=sorted(target_set),
    )

    start = time.monotonic()

    try:
        report.input_sha256 = _sha256_file(input_apk)
    except OSError as exc:
        raise ValidationError(f"Calcul du SHA-256 impossible : {exc}") from exc

    output_apk.parent.mkdir(parents=True, exist_ok=True)
    tmp_output = output_apk.with_name(
        f".{output_apk.name}.tmp-{os.getpid()}-{int(start)}"
    )

    detected_archs: set = set()
    kept_archs: set = set()
    removed_archs: set = set()

    try:
        with zipfile.ZipFile(input_apk, "r") as zf_in:
            total_entries = len(zf_in.infolist())
            report.total_entries = total_entries

            try:
                with zipfile.ZipFile(
                    tmp_output,
                    "w",
                    compression=zipfile.ZIP_DEFLATED,
                    allowZip64=True,
                ) as zf_out:
                    for info in zf_in.infolist():
                        name = info.filename
                        arch = _extract_arch_from_entry(name)

                        if arch is not None:
                            detected_archs.add(arch)

                        if (
                            arch is not None
                            and arch not in target_set
                        ):
                            removed_archs.add(arch)
                            report.removed_entries += 1
                            if _is_native_lib_entry(name):
                                report.removed_native_libs += 1
                                if len(report.removed_native_lib_names) < 200:
                                    report.removed_native_lib_names.append(name)
                            continue

                        if arch is not None:
                            kept_archs.add(arch)

                        if info.is_dir():
                            zi = _build_zipinfo(info, use_stored=False)
                            zi.compress_type = zipfile.ZIP_STORED
                            zi.file_size = 0
                            zi.compress_size = 0
                            try:
                                zf_out.writestr(zi, b"")
                            except (OSError, RuntimeError) as exc:
                                raise RepackError(
                                    f"Écriture du répertoire {name} impossible : {exc}"
                                ) from exc
                            report.kept_entries += 1
                            continue

                        try:
                            data = zf_in.read(info)
                        except (zipfile.BadZipFile, RuntimeError, OSError) as exc:
                            raise RepackError(
                                f"Lecture de l'entrée {name} impossible : {exc}"
                            ) from exc

                        is_so = _is_native_lib_entry(name)
                        use_stored = is_so or _should_store_uncompressed(name)

                        zi = _build_zipinfo(info, use_stored=use_stored)

                        if is_so:
                            try:
                                _write_aligned_entry(zf_out, zi, data, ALIGNMENT)
                            except (OSError, RuntimeError, ValueError) as exc:
                                raise RepackError(
                                    f"Écriture alignée de {name} impossible : {exc}"
                                ) from exc
                            report.kept_native_libs += 1
                        else:
                            try:
                                zf_out.writestr(zi, data)
                            except (OSError, RuntimeError) as exc:
                                raise RepackError(
                                    f"Écriture de {name} impossible : {exc}"
                                ) from exc

                        report.kept_entries += 1
            except zipfile.BadZipFile as exc:
                raise RepackError(
                    f"Erreur ZIP lors de la reconstruction : {exc}"
                ) from exc
    except (ValidationError, RepackError):
        _safe_unlink(tmp_output)
        raise
    except OSError as exc:
        _safe_unlink(tmp_output)
        raise RepackError(f"Erreur d'E/S lors du repack : {exc}") from exc
    except Exception:
        _safe_unlink(tmp_output)
        raise

    try:
        if tmp_output.stat().st_size < MIN_APK_SIZE:
            raise RepackError(
                f"APK de sortie trop petit ({tmp_output.stat().st_size} octets)"
            )
        os.replace(tmp_output, output_apk)
    except OSError as exc:
        _safe_unlink(tmp_output)
        raise RepackError(f"Finalisation de l'APK impossible : {exc}") from exc

    report.detected_architectures = sorted(detected_archs)
    report.kept_architectures = sorted(kept_archs)
    report.removed_architectures = sorted(removed_archs)
    report.output_size = output_apk.stat().st_size

    try:
        report.output_sha256 = _sha256_file(output_apk)
    except OSError as exc:
        raise RepackError(f"Calcul du SHA-256 de sortie impossible : {exc}") from exc

    verified, vwarn, verr = _verify_output(output_apk, normalized_targets)
    report.output_verified = verified
    report.warnings.extend(vwarn)
    report.errors.extend(verr)

    report.duration_seconds = round(time.monotonic() - start, 3)

    if not report.detected_architectures:
        report.warnings.append(
            "Aucune bibliothèque native détectée dans l'APK d'entrée"
        )

    if report.errors:
        LOGGER.error(
            "Vérification de sortie échouée : %s", "; ".join(report.errors)
        )
    elif report.warnings:
        for w in report.warnings:
            LOGGER.warning("%s", w)

    return report

def _safe_unlink(path: Path) -> None:
    try:
        if path.exists():
            path.unlink()
    except OSError:
        LOGGER.debug("Suppression impossible : %s", path)

def _build_cli_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="builder_64bit",
        description=(
            "Filtre les bibliothèques natives d'un APK pour ne conserver "
            "que les architectures 64-bit cibles et reconstruit une archive "
            "APK valide."
        ),
    )
    parser.add_argument(
        "input",
        type=Path,
        help="APK source",
    )
    parser.add_argument(
        "output",
        type=Path,
        help="APK de sortie (64-bit)",
    )
    parser.add_argument(
        "--arch",
        action="append",
        default=None,
        help=(
            "Architecture 64-bit à conserver (répétable). "
            f"Valeurs possibles : {', '.join(SIXTY_FOUR_BIT_ARCHS)}"
        ),
    )
    parser.add_argument(
        "--no-verify",
        action="store_true",
        help="Désactive la vérification finale de l'APK de sortie",
    )
    parser.add_argument(
        "--report",
        type=Path,
        default=None,
        help="Chemin d'écriture du rapport JSON",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
    )
    return parser

def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_cli_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

    targets: Optional[List[str]] = args.arch if args.arch else None

    try:
        report = build_64bit_apk(
            input_apk=args.input,
            output_apk=args.output,
            target_architectures=targets,
            keep_all_64bit=True,
        )
    except ValidationError as exc:
        LOGGER.error("Validation échouée : %s", exc)
        sys.stderr.write(f"builder_64bit: {exc}\n")
        return 2
    except RepackError as exc:
        LOGGER.error("Reconstruction échouée : %s", exc)
        sys.stderr.write(f"builder_64bit: {exc}\n")
        return 3
    except Exception:
        LOGGER.exception("Erreur inattendue")
        sys.stderr.write("builder_64bit: erreur inattendue\n")
        return 4

    payload = asdict(report)
    serialized = json.dumps(payload, ensure_ascii=False, indent=2)

    if args.report is not None:
        try:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            tmp = args.report.with_suffix(args.report.suffix + ".tmp")
            with tmp.open("w", encoding="utf-8") as fh:
                fh.write(serialized)
                fh.write("\n")
            os.replace(tmp, args.report)
        except OSError as exc:
            LOGGER.error("Écriture du rapport impossible : %s", exc)
            sys.stderr.write(f"builder_64bit: rapport non écrit : {exc}\n")
            return 5

    sys.stdout.write(serialized)
    sys.stdout.write("\n")

    if report.errors and not args.no_verify:
        return 1
    return 0

if __name__ == "__main__":
    sys.exit(main())
