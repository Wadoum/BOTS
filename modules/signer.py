from __future__ import annotations

import argparse
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

LOGGER = logging.getLogger("signer")
LOGGER.addHandler(logging.NullHandler())

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_KEYSTORE_DIR = PROJECT_ROOT / "configs" / "keystore"
DEFAULT_SIGNED_DIR = PROJECT_ROOT / "data" / "output" / "signed"
DEFAULT_LOG_DIR = PROJECT_ROOT / "data" / "logs"

DEFAULT_UBER_JAR = PROJECT_ROOT / "tools" / "uber-apk-signer.jar"
DEFAULT_APKSIGNER = "apksigner"
DEFAULT_KEYTOOL = "keytool"
DEFAULT_ZIPALIGN = "zipalign"

DEFAULT_KEYSTORE_NAME = "release.jks"
DEFAULT_KEY_ALIAS = "bots-release"
DEFAULT_KEYSTORE_PASSWORD_ENV = "KEYSTORE_PASSWORD"
DEFAULT_KEY_PASSWORD_ENV = "KEY_PASSWORD"
DEFAULT_KEY_ALIAS_ENV = "KEYSTORE_ALIAS"
DEFAULT_UBER_KEYSTORE_ENV = "UBER_KEYSTORE"
DEFAULT_UBER_ALIAS_ENV = "UBER_KEYSTORE_ALIAS"
DEFAULT_UBER_KEYSTORE_PASS_ENV = "UBER_KEYSTORE_PASSWORD"
DEFAULT_UBER_KEY_PASS_ENV = "UBER_KEY_PASSWORD"

DEFAULT_TIMEOUT_SECONDS = 600
DEFAULT_RETRY_ATTEMPTS = 2
DEFAULT_RETRY_DELAY = 5.0
MAX_RETRY_DELAY = 60.0

SIGNATURE_SCHEME_FLAGS: Dict[str, str] = {
    "v1": "--v1-signing-enabled",
    "v2": "--v2-signing-enabled",
    "v3": "--v3-signing-enabled",
    "v4": "--v4-signing-enabled",
}

ALLOWED_SIGNATURE_SCHEMES: Tuple[str, ...] = ("v1", "v2", "v3", "v4")

APK_EXTENSIONS: Tuple[str, ...] = (".apk", ".apks", ".apkm", ".xapk")

UBER_OUTPUT_SUFFIXES: Tuple[str, ...] = (
    "-aligned-signed.apk",
    "-signed.apk",
    "-aligned.apk",
)

class SignerError(Exception):
    pass

class SignerConfigurationError(SignerError):
    pass

class SignerExecutionError(SignerError):
    def __init__(self, message: str, returncode: Optional[int] = None, stderr: str = "") -> None:
        super().__init__(message)
        self.returncode = returncode
        self.stderr = stderr

class SignerVerificationError(SignerError):
    pass

@dataclass
class SignRequest:
    input_apk: Path
    output_dir: Path
    keystore: Optional[Path] = None
    keystore_password: Optional[str] = None
    key_alias: Optional[str] = None
    key_password: Optional[str] = None
    signer_name: Optional[str] = None
    enable_v1: bool = True
    enable_v2: bool = True
    enable_v3: bool = True
    enable_v4: bool = False
    zipalign: bool = True
    force_overwrite: bool = True
    allow_resign: bool = True
    dry_run: bool = False
    timeout: int = DEFAULT_TIMEOUT_SECONDS
    retries: int = DEFAULT_RETRY_ATTEMPTS
    retry_delay: float = DEFAULT_RETRY_DELAY

@dataclass
class SignResult:
    success: bool
    input_apk: str
    output_apk: Optional[str]
    signatures: Dict[str, bool] = field(default_factory=dict)
    returncode: Optional[int] = None
    stdout: str = ""
    stderr: str = ""
    duration_seconds: float = 0.0
    attempts: int = 1
    verified: bool = False
    verification_details: str = ""
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

def _find_executable(*candidates: str) -> Optional[str]:
    for name in candidates:
        if not name:
            continue
        path = shutil.which(name)
        if path:
            return path
    return None

def _resolve_java() -> str:
    java = _find_executable("java")
    if java is None:
        raise SignerConfigurationError(
            "Le binaire 'java' est introuvable dans le PATH. "
            "Installez un JRE/JDK (openjdk-17-jre-headless)."
        )
    return java

def _validate_input_apk(path: Path) -> None:
    if not path.exists():
        raise SignerConfigurationError(f"APK d'entrée introuvable : {path}")
    if not path.is_file():
        raise SignerConfigurationError(f"Chemin non régulier : {path}")
    size = path.stat().st_size
    if size < 1024:
        raise SignerConfigurationError(
            f"APK d'entrée trop petit ({size} octets)"
        )
    try:
        with path.open("rb") as fh:
            magic = fh.read(2)
    except OSError as exc:
        raise SignerConfigurationError(
            f"Lecture de l'APK impossible : {exc}"
        ) from exc
    if magic != b"PK":
        raise SignerConfigurationError(
            f"Le fichier {path} n'est pas une archive APK/ZIP valide"
        )

def _read_env_secret(name: str) -> Optional[str]:
    value = os.environ.get(name)
    if value is None:
        return None
    value = value.strip()
    if not value:
        return None
    return value

def _resolve_credentials() -> Tuple[Optional[str], Optional[str], Optional[str]]:
    keystore_password = _read_env_secret(DEFAULT_UBER_KEYSTORE_PASS_ENV) or \
                        _read_env_secret(DEFAULT_KEYSTORE_PASSWORD_ENV)
    key_password = _read_env_secret(DEFAULT_UBER_KEY_PASS_ENV) or \
                   _read_env_secret(DEFAULT_KEY_PASSWORD_ENV)
    key_alias = _read_env_secret(DEFAULT_UBER_ALIAS_ENV) or \
                _read_env_secret(DEFAULT_KEY_ALIAS_ENV)
    return keystore_password, key_password, key_alias

def _resolve_keystore(request: SignRequest) -> Optional[Path]:
    if request.keystore is not None:
        path = Path(request.keystore)
        if not path.exists():
            raise SignerConfigurationError(
                f"Keystore spécifié introuvable : {path}"
            )
        if path.stat().st_size < 64:
            raise SignerConfigurationError(
                f"Keystore suspect (fichier trop petit) : {path}"
            )
        return path

    env_path = _read_env_secret(DEFAULT_UBER_KEYSTORE_ENV)
    if env_path:
        candidate = Path(env_path)
        if candidate.exists():
            return candidate

    default_path = DEFAULT_KEYSTORE_DIR / DEFAULT_KEYSTORE_NAME
    if default_path.exists():
        return default_path

    return None

def _build_uber_command(
    request: SignRequest,
    uber_jar: Path,
    keystore: Optional[Path],
    keystore_password: Optional[str],
    key_password: Optional[str],
    key_alias: Optional[str],
) -> List[str]:
    cmd: List[str] = [
        _resolve_java(),
        "-jar",
        str(uber_jar),
        "--apks",
        str(request.input_apk),
        "--out",
        str(request.output_dir),
    ]

    if keystore is not None:
        cmd.extend(["--ks", str(keystore)])

    if key_alias:
        cmd.extend(["--ksAlias", key_alias])

    if keystore_password:
        cmd.extend(["--ksPass", keystore_password])

    if key_password:
        cmd.extend(["--keyPass", key_password])

    if request.signer_name:
        cmd.extend(["--ksName", request.signer_name])

    if request.allow_resign:
        cmd.append("--allowResign")

    if request.force_overwrite:
        cmd.append("--overwrite")

    if request.zipalign:
        cmd.append("--zipAlign")

    return cmd

def _build_apksigner_command(
    request: SignRequest,
    apksigner_bin: str,
    keystore: Path,
    keystore_password: str,
    key_password: str,
    key_alias: str,
) -> List[str]:
    cmd: List[str] = [
        apksigner_bin,
        "sign",
        "--ks",
        str(keystore),
        "--ks-pass",
        f"pass:{keystore_password}",
        "--key-pass",
        f"pass:{key_password}",
        "--ks-key-alias",
        key_alias,
        "--out",
        str(request.output_dir / f"{request.input_apk.stem}-signed.apk"),
    ]

    for scheme, flag in SIGNATURE_SCHEME_FLAGS.items():
        enabled = getattr(request, f"enable_{scheme}", False)
        cmd.extend([flag, "true" if enabled else "false"])

    if request.force_overwrite:
        cmd.append("--force")

    cmd.append(str(request.input_apk))
    return cmd

def _run_subprocess(
    cmd: Sequence[str],
    timeout: int,
) -> Tuple[int, str, str, float]:
    start = time.monotonic()
    try:
        proc = subprocess.run(
            list(cmd),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        duration = time.monotonic() - start
        raise SignerExecutionError(
            f"Délai d'exécution dépassé ({timeout}s)",
            returncode=None,
            stderr=str(exc),
        ) from exc
    except OSError as exc:
        duration = time.monotonic() - start
        raise SignerExecutionError(
            f"Exécution impossible : {exc}",
            returncode=None,
            stderr=str(exc),
        ) from exc
    duration = time.monotonic() - start
    return proc.returncode, proc.stdout or "", proc.stderr or "", duration

def _is_retryable(returncode: Optional[int], stderr: str) -> bool:
    if returncode is None:
        return True
    if returncode == 0:
        return False
    if returncode == 1:
        return True
    lowered = stderr.lower()
    for pattern in ("out of memory", "oom", "temporarily unavailable",
                    "connection reset", "timeout", "resource busy",
                    "permission denied (transient)"):
        if pattern in lowered:
            return True
    return returncode >= 124

def _detect_uber_outputs(output_dir: Path, stem: str) -> List[Path]:
    if not output_dir.exists():
        return []
    candidates: List[Path] = []
    for path in output_dir.iterdir():
        if not path.is_file():
            continue
        if path.suffix.lower() != ".apk":
            continue
        name = path.name
        if name.startswith(stem) or stem in name:
            candidates.append(path)
            continue
        for suffix in UBER_OUTPUT_SUFFIXES:
            if name.endswith(suffix):
                candidates.append(path)
                break
    return sorted(candidates, key=lambda p: p.stat().st_mtime, reverse=True)

def _verify_apk_signature(
    apk_path: Path,
    apksigner_bin: Optional[str],
    timeout: int = 120,
) -> Tuple[bool, str, List[str]]:
    warnings: List[str] = []

    if apksigner_bin is None:
        return False, "apksigner indisponible, vérification ignorée", warnings

    cmd = [apksigner_bin, "verify", "--verbose", "--print-certs", str(apk_path)]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        return False, f"Vérification impossible : {exc}", warnings

    output = (proc.stdout or "") + "\n" + (proc.stderr or "")
    if proc.returncode != 0:
        return False, output.strip(), warnings

    lowered = output.lower()
    if "does not verify" in lowered:
        return False, output.strip(), warnings

    return True, output.strip(), warnings

def sign_apk(request: SignRequest) -> SignResult:
    input_apk = Path(request.input_apk)
    output_dir = Path(request.output_dir)

    _validate_input_apk(input_apk)
    output_dir.mkdir(parents=True, exist_ok=True)

    if request.dry_run:
        return SignResult(
            success=True,
            input_apk=str(input_apk),
            output_apk=None,
            warnings=["dry_run activé : aucune signature effectuée"],
        )

    env_ks_pass, env_key_pass, env_alias = _resolve_credentials()

    keystore = _resolve_keystore(request)
    keystore_password = request.keystore_password or env_ks_pass
    key_password = request.key_password or env_key_pass or keystore_password
    key_alias = request.key_alias or env_alias or DEFAULT_KEY_ALIAS

    warnings: List[str] = []
    errors: List[str] = []

    if keystore is None:
        warnings.append(
            "Aucun keystore fourni : uber-apk-signer utilisera son "
            "keystore de débogage intégré. La signature ne sera pas "
            "apte à la distribution."
        )

    if keystore is not None and not keystore_password:
        errors.append(
            "Un keystore a été fourni mais aucun mot de passe n'est "
            "disponible. Définissez "
            f"{DEFAULT_UBER_KEYSTORE_PASS_ENV} ou "
            f"{DEFAULT_KEYSTORE_PASSWORD_ENV}."
        )
        return SignResult(
            success=False,
            input_apk=str(input_apk),
            output_apk=None,
            errors=errors,
            warnings=warnings,
        )

    uber_jar = DEFAULT_UBER_JAR
    apksigner_bin = _find_executable(DEFAULT_APKSIGNER)

    if not uber_jar.exists():
        if apksigner_bin is None:
            raise SignerConfigurationError(
                "Ni uber-apk-signer.jar ni apksigner ne sont disponibles. "
                f"Attendu : {uber_jar} ou apksigner dans le PATH."
            )
        if keystore is None:
            raise SignerConfigurationError(
                "apksigner nécessite un keystore explicite ; "
                "aucun keystore n'a été fourni."
            )
        if not keystore_password or not key_password or not key_alias:
            raise SignerConfigurationError(
                "Credentials de signature incomplets pour apksigner."
            )

        cmd = _build_apksigner_command(
            request=request,
            apksigner_bin=apksigner_bin,
            keystore=keystore,
            keystore_password=keystore_password,
            key_password=key_password,
            key_alias=key_alias,
        )

        last_error: Optional[SignerExecutionError] = None
        attempts = 0

        for attempt in range(1, request.retries + 1):
            attempts = attempt
            try:
                rc, stdout, stderr, duration = _run_subprocess(cmd, request.timeout)
            except SignerExecutionError as exc:
                last_error = exc
                if attempt < request.retries and _is_retryable(exc.returncode, exc.stderr):
                    delay = min(request.retry_delay * (2 ** (attempt - 1)), MAX_RETRY_DELAY)
                    time.sleep(delay)
                    continue
                raise

            if rc == 0:
                break

            if not _is_retryable(rc, stderr):
                raise SignerExecutionError(
                    f"apksigner a échoué (code {rc})",
                    returncode=rc,
                    stderr=stderr,
                )

            last_error = SignerExecutionError(
                f"apksigner a échoué (code {rc})",
                returncode=rc,
                stderr=stderr,
            )
            if attempt < request.retries:
                delay = min(request.retry_delay * (2 ** (attempt - 1)), MAX_RETRY_DELAY)
                time.sleep(delay)
        else:
            if last_error is not None:
                raise last_error
            raise SignerExecutionError("Échec inattendu d'apksigner")

        expected = output_dir / f"{input_apk.stem}-signed.apk"
        if not expected.exists():
            outputs = _detect_uber_outputs(output_dir, input_apk.stem)
            expected = outputs[0] if outputs else None

        verified = False
        details = ""
        if expected is not None and apksigner_bin is not None:
            verified, details, vwarn = _verify_apk_signature(expected, apksigner_bin)
            warnings.extend(vwarn)

        return SignResult(
            success=True,
            input_apk=str(input_apk),
            output_apk=str(expected) if expected else None,
            returncode=rc,
            stdout=stdout,
            stderr=stderr,
            duration_seconds=round(duration, 3),
            attempts=attempts,
            verified=verified,
            verification_details=details,
            warnings=warnings,
            errors=errors,
        )

    cmd = _build_uber_command(
        request=request,
        uber_jar=uber_jar,
        keystore=keystore,
        keystore_password=keystore_password,
        key_password=key_password,
        key_alias=key_alias,
    )

    LOGGER.info("Exécution de uber-apk-signer (commande tronquée)")
    LOGGER.debug("Commande complète : %s", " ".join(cmd))

    last_error: Optional[SignerExecutionError] = None
    attempts = 0
    stdout = ""
    stderr = ""
    rc = 1
    duration = 0.0

    for attempt in range(1, request.retries + 1):
        attempts = attempt
        try:
            rc, stdout, stderr, duration = _run_subprocess(cmd, request.timeout)
        except SignerExecutionError as exc:
            last_error = exc
            if attempt < request.retries and _is_retryable(exc.returncode, exc.stderr):
                delay = min(request.retry_delay * (2 ** (attempt - 1)), MAX_RETRY_DELAY)
                time.sleep(delay)
                continue
            raise

        if rc == 0:
            break

        if not _is_retryable(rc, stderr):
            raise SignerExecutionError(
                f"uber-apk-signer a échoué (code {rc})",
                returncode=rc,
                stderr=stderr,
            )

        last_error = SignerExecutionError(
            f"uber-apk-signer a échoué (code {rc})",
            returncode=rc,
            stderr=stderr,
        )
        if attempt < request.retries:
            delay = min(request.retry_delay * (2 ** (attempt - 1)), MAX_RETRY_DELAY)
            time.sleep(delay)

    if rc != 0 and last_error is not None:
        raise last_error

    outputs = _detect_uber_outputs(output_dir, input_apk.stem)
    if not outputs:
        raise SignerExecutionError(
            "uber-apk-signer s'est terminé avec succès mais aucun APK "
            f"signé n'a été trouvé dans {output_dir}",
            returncode=rc,
            stderr=stderr,
        )

    signed_apk = outputs[0]

    if signed_apk.stat().st_size < 1024:
        errors.append(
            f"APK signé suspect (taille={signed_apk.stat().st_size} octets)"
        )
        return SignResult(
            success=False,
            input_apk=str(input_apk),
            output_apk=str(signed_apk),
            returncode=rc,
            stdout=stdout,
            stderr=stderr,
            duration_seconds=round(duration, 3),
            attempts=attempts,
            warnings=warnings,
            errors=errors,
        )

    verified = False
    details = ""
    if apksigner_bin is not None:
        verified, details, vwarn = _verify_apk_signature(signed_apk, apksigner_bin)
        warnings.extend(vwarn)
    else:
        warnings.append(
            "apksigner indisponible : signature non vérifiée indépendamment"
        )

    signatures: Dict[str, bool] = {}
    if details:
        lowered = details.lower()
        for scheme in ALLOWED_SIGNATURE_SCHEMES:
            marker = f"verified using {scheme} scheme"
            if marker in lowered:
                line_match = re.search(
                    rf"verified using {scheme} scheme[^:]*:\s*(true|false)",
                    lowered,
                )
                if line_match:
                    signatures[scheme] = line_match.group(1) == "true"

    return SignResult(
        success=True,
        input_apk=str(input_apk),
        output_apk=str(signed_apk),
        signatures=signatures,
        returncode=rc,
        stdout=stdout,
        stderr=stderr,
        duration_seconds=round(duration, 3),
        attempts=attempts,
        verified=verified,
        verification_details=details,
        warnings=warnings,
        errors=errors,
    )

def _build_cli_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="signer",
        description=(
            "Signe un APK via uber-apk-signer (ou apksigner en secours), "
            "avec zipalign optionnel et vérification post-signature."
        ),
    )
    parser.add_argument("input", type=Path, help="APK d'entrée")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_SIGNED_DIR,
        help="Répertoire de sortie",
    )
    parser.add_argument("--keystore", type=Path, default=None)
    parser.add_argument("--key-alias", default=None)
    parser.add_argument("--signer-name", default=None)
    parser.add_argument("--no-v1", action="store_true")
    parser.add_argument("--no-v2", action="store_true")
    parser.add_argument("--no-v3", action="store_true")
    parser.add_argument("--v4", action="store_true")
    parser.add_argument("--no-zipalign", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
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

    request = SignRequest(
        input_apk=args.input,
        output_dir=args.output_dir,
        keystore=args.keystore,
        key_alias=args.key_alias,
        signer_name=args.signer_name,
        enable_v1=not args.no_v1,
        enable_v2=not args.no_v2,
        enable_v3=not args.no_v3,
        enable_v4=args.v4,
        zipalign=not args.no_zipalign,
        dry_run=args.dry_run,
    )

    try:
        result = sign_apk(request)
    except SignerConfigurationError as exc:
        LOGGER.error("Configuration invalide : %s", exc)
        sys.stderr.write(f"signer: {exc}\n")
        return 2
    except SignerExecutionError as exc:
        LOGGER.error("Échec de signature : %s", exc)
        if exc.stderr:
            LOGGER.debug("stderr : %s", exc.stderr.strip()[-500:])
        sys.stderr.write(f"signer: {exc}\n")
        return 3
    except Exception:
        LOGGER.exception("Erreur inattendue")
        sys.stderr.write("signer: erreur inattendue\n")
        return 4

    payload = asdict(result)
    serialized = json.dumps(payload, ensure_ascii=False, indent=2)
    sys.stdout.write(serialized)
    sys.stdout.write("\n")

    return 0 if result.success else 1

if __name__ == "__main__":
    sys.exit(main())
