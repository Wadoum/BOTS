from __future__ import annotations

import argparse
import json
import logging
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

LOGGER = logging.getLogger("patcher_core")
LOGGER.addHandler(logging.NullHandler())

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG_PATH = PROJECT_ROOT / "configs" / "morphe-config.json"
DEFAULT_WHITELIST_PATH = PROJECT_ROOT / "configs" / "patch_whitelist.txt"
DEFAULT_MORPHE_JAR = PROJECT_ROOT / "tools" / "morphe-cli.jar"
DEFAULT_KEYSTORE = PROJECT_ROOT / "tools" / "morphe.keystore"
DEFAULT_KEYSTORE_ALIAS = "Morphe"
DEFAULT_KEYSTORE_PASSWORD = ""
DEFAULT_TIMEOUT_SECONDS = 1800
DEFAULT_RETRY_ATTEMPTS = 2
DEFAULT_RETRY_DELAY = 5.0
MAX_RETRY_DELAY = 60.0
SUPPORTED_ARCHITECTURES = ("arm64-v8a", "armeabi-v7a", "x86", "x86_64")
ALLOWED_BYTECODE_MODES = ("FULL", "STRIP_SAFE", "STRIP_FAST")

class PatcherError(Exception):
    pass

class ConfigurationError(PatcherError):
    pass

class MorpheExecutionError(PatcherError):
    def __init__(self, message: str, returncode: Optional[int] = None, stderr: str = "") -> None:
        super().__init__(message)
        self.returncode = returncode
        self.stderr = stderr

@dataclass
class PatchRequest:
    apk_path: Path
    output_path: Path
    patches_mpp: Optional[Path] = None
    patches_repo_url: Optional[str] = None
    include_patches: List[str] = field(default_factory=list)
    exclude_patches: List[str] = field(default_factory=list)
    patch_options: Dict[str, Any] = field(default_factory=dict)
    options_file: Optional[Path] = None
    keystore: Optional[Path] = None
    keystore_password: Optional[str] = None
    keystore_alias: Optional[str] = None
    keystore_entry_password: Optional[str] = None
    signer_name: Optional[str] = None
    strip_architectures: List[str] = field(default_factory=list)
    bytecode_mode: Optional[str] = None
    force: bool = False
    unsigned: bool = False
    continue_on_error: bool = True
    disable_purge: bool = False
    prerelease: bool = False
    result_file: Optional[Path] = None
    timeout: int = DEFAULT_TIMEOUT_SECONDS
    retries: int = DEFAULT_RETRY_ATTEMPTS
    retry_delay: float = DEFAULT_RETRY_DELAY

@dataclass
class PatchResult:
    success: bool
    output_path: Optional[Path]
    returncode: Optional[int]
    stdout: str
    stderr: str
    duration_seconds: float
    attempts: int
    report_path: Optional[Path] = None

def _load_json(path: Path) -> Dict[str, Any]:
    if not path.exists():
        raise ConfigurationError(f"Fichier de configuration introuvable : {path}")
    try:
        with path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigurationError(f"Lecture de {path} impossible : {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigurationError(f"Le fichier {path} doit contenir un objet JSON")
    return data

def _load_whitelist(path: Path) -> Dict[str, List[str]]:
    if not path.exists():
        raise ConfigurationError(f"Liste blanche introuvable : {path}")
    sections: Dict[str, List[str]] = {}
    current: Optional[str] = None
    try:
        with path.open("r", encoding="utf-8") as fh:
            for raw in fh:
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                if line.startswith("[") and line.endswith("]"):
                    current = line[1:-1]
                    sections.setdefault(current, [])
                elif current is not None:
                    sections[current].append(line)
    except OSError as exc:
        raise ConfigurationError(f"Lecture de {path} impossible : {exc}") from exc
    return sections

def _resolve_java_binary() -> str:
    java = shutil.which("java")
    if java is None:
        raise ConfigurationError("Binaire java introuvable dans le PATH")
    return java

def _normalize_architecture(arch: str) -> str:
    if not isinstance(arch, str):
        raise ConfigurationError("L'architecture doit être une chaîne")
    normalized = arch.strip().lower()
    if normalized not in SUPPORTED_ARCHITECTURES:
        raise ConfigurationError(
            f"Architecture non supportée : {arch!r}. "
            f"Valeurs autorisées : {', '.join(SUPPORTED_ARCHITECTURES)}"
        )
    return normalized

class MorphePatcher:
    def __init__(
        self,
        morphe_jar: Path = DEFAULT_MORPHE_JAR,
        config_path: Path = DEFAULT_CONFIG_PATH,
        whitelist_path: Path = DEFAULT_WHITELIST_PATH,
        keystore: Path = DEFAULT_KEYSTORE,
    ) -> None:
        self.morphe_jar = Path(morphe_jar)
        self.config_path = Path(config_path)
        self.whitelist_path = Path(whitelist_path)
        self.keystore = Path(keystore)
        self._config: Optional[Dict[str, Any]] = None
        self._whitelist: Optional[Dict[str, List[str]]] = None
        self._java: Optional[str] = None

    @property
    def java(self) -> str:
        if self._java is None:
            self._java = _resolve_java_binary()
        return self._java

    @property
    def config(self) -> Dict[str, Any]:
        if self._config is None:
            self._config = _load_json(self.config_path)
        return self._config

    @property
    def whitelist(self) -> Dict[str, List[str]]:
        if self._whitelist is None:
            self._whitelist = _load_whitelist(self.whitelist_path)
        return self._whitelist

    def _validate_jar(self) -> None:
        if not self.morphe_jar.exists():
            raise ConfigurationError(f"Morphe CLI introuvable : {self.morphe_jar}")
        if self.morphe_jar.stat().st_size < 1024:
            raise ConfigurationError(f"Morphe CLI corrompu : {self.morphe_jar}")

    def _validate_apk(self, apk: Path) -> None:
        if not apk.exists():
            raise ConfigurationError(f"APK source introuvable : {apk}")
        if apk.stat().st_size < 1024:
            raise ConfigurationError(f"APK source trop petit : {apk}")
        try:
            with apk.open("rb") as fh:
                magic = fh.read(2)
        except OSError as exc:
            raise ConfigurationError(f"Lecture de l'APK impossible : {exc}") from exc
        if magic != b"PK":
            raise ConfigurationError(
                f"Le fichier {apk} n'est pas une archive ZIP/APK valide"
            )

    def _validate_patch_name(self, name: str) -> None:
        if not isinstance(name, str) or not name.strip():
            raise ConfigurationError("Nom de patch invalide")
        allowed = set()
        for section in ("PATCHES_ADS", "PATCHES_ANALYTICS", "PATCHES_PREMIUM",
                        "PATCHES_ROOT", "PATCHES_SIGNATURE", "PATCHES_NETWORK",
                        "PATCHES_CUSTOMIZATION", "PATCHES_FEATURES",
                        "PATCHES_OPTIMIZATION", "PATCHES_LIMITS",
                        "PATCHES_SECURITY", "PATCHES_MISC"):
            allowed.update(self.whitelist.get(section, []))
        if allowed and name not in allowed:
            raise ConfigurationError(f"Patch non autorisé par la liste blanche : {name}")

    def _build_command(self, request: PatchRequest) -> List[str]:
        if request.patches_mpp is None and request.patches_repo_url is None:
            raise ConfigurationError("Un fichier .mpp ou une URL de dépôt est requis")

        cmd: List[str] = [self.java, "-jar", str(self.morphe_jar), "patch"]

        if request.patches_mpp is not None:
            if not request.patches_mpp.exists():
                raise ConfigurationError(
                    f"Fichier de patches introuvable : {request.patches_mpp}"
                )
            cmd.extend(["--patches", str(request.patches_mpp)])
        else:
            cmd.extend(["--patches", str(request.patches_repo_url)])

        if request.prerelease:
            cmd.append("--prerelease")

        for name in request.include_patches:
            self._validate_patch_name(name)
            cmd.extend(["--enable", name])

        for name in request.exclude_patches:
            cmd.extend(["--disable", name])

        if request.include_patches and request.exclude_patches:
            cmd.append("--exclusive")

        for key, value in request.patch_options.items():
            if not isinstance(key, str) or not key:
                raise ConfigurationError("Clé d'option de patch invalide")
            if isinstance(value, bool):
                value_str = "true" if value else "false"
            else:
                value_str = str(value)
            cmd.extend(["--options", f"{key}={value_str}"])

        if request.options_file is not None:
            if not request.options_file.exists():
                raise ConfigurationError(
                    f"Fichier d'options introuvable : {request.options_file}"
                )
            cmd.extend(["--options-file", str(request.options_file)])

        if request.keystore is not None:
            if not request.keystore.exists():
                raise ConfigurationError(
                    f"Keystore introuvable : {request.keystore}"
                )
            cmd.extend(["--keystore", str(request.keystore)])

        if request.keystore_password is not None:
            cmd.extend(["--keystore-password", request.keystore_password])

        if request.keystore_alias is not None:
            cmd.extend(["--keystore-entry-alias", request.keystore_alias])

        if request.keystore_entry_password is not None:
            cmd.extend(["--keystore-entry-password", request.keystore_entry_password])

        if request.signer_name is not None:
            cmd.extend(["--signer", request.signer_name])

        if request.strip_architectures:
            normalized = [_normalize_architecture(a) for a in request.strip_architectures]
            cmd.extend(["--striplibs", ",".join(normalized)])

        if request.bytecode_mode is not None:
            if request.bytecode_mode not in ALLOWED_BYTECODE_MODES:
                raise ConfigurationError(
                    f"Mode bytecode invalide : {request.bytecode_mode!r}. "
                    f"Valeurs : {', '.join(ALLOWED_BYTECODE_MODES)}"
                )
            cmd.extend(["--bytecode-mode", request.bytecode_mode])

        if request.force:
            cmd.append("--force")

        if request.unsigned:
            cmd.append("--unsigned")

        if request.continue_on_error:
            cmd.append("--continue-on-error")

        if request.disable_purge:
            cmd.append("--disable-purge")

        if request.result_file is not None:
            request.result_file.parent.mkdir(parents=True, exist_ok=True)
            cmd.extend(["--result-file", str(request.result_file)])

        cmd.extend(["--out", str(request.output_path)])
        cmd.append(str(request.apk_path))
        return cmd

    def _run_once(
        self,
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
            raise MorpheExecutionError(
                f"Délai d'exécution dépassé ({timeout}s)",
                returncode=None,
                stderr=str(exc),
            ) from exc
        except OSError as exc:
            duration = time.monotonic() - start
            raise MorpheExecutionError(
                f"Exécution impossible de Morphe CLI : {exc}",
                returncode=None,
                stderr=str(exc),
            ) from exc
        duration = time.monotonic() - start
        return proc.returncode, proc.stdout or "", proc.stderr or "", duration

    def patch(self, request: PatchRequest) -> PatchResult:
        self._validate_jar()
        self._validate_apk(request.apk_path)

        request.output_path.parent.mkdir(parents=True, exist_ok=True)

        cmd = self._build_command(request)
        LOGGER.info("Exécution de Morphe CLI : %s", " ".join(cmd[:6]) + " ...")

        last_error: Optional[MorpheExecutionError] = None
        attempts = 0

        for attempt in range(1, request.retries + 1):
            attempts = attempt
            try:
                rc, stdout, stderr, duration = self._run_once(cmd, request.timeout)
            except MorpheExecutionError as exc:
                last_error = exc
                LOGGER.warning(
                    "Tentative %d/%d échouée : %s",
                    attempt, request.retries, exc,
                )
                if attempt < request.retries:
                    delay = min(
                        request.retry_delay * (2 ** (attempt - 1)),
                        MAX_RETRY_DELAY,
                    )
                    time.sleep(delay)
                    continue
                raise

            if rc == 0:
                if not request.output_path.exists():
                    raise MorpheExecutionError(
                        "Morphe CLI a retourné un code 0 mais aucun APK de sortie",
                        returncode=rc,
                        stderr=stderr,
                    )
                report = request.result_file if request.result_file and request.result_file.exists() else None
                return PatchResult(
                    success=True,
                    output_path=request.output_path,
                    returncode=rc,
                    stdout=stdout,
                    stderr=stderr,
                    duration_seconds=duration,
                    attempts=attempt,
                    report_path=report,
                )

            snippet = stderr.strip()[-500:] if stderr else ""
            LOGGER.error(
                "Morphe CLI a échoué (code %s) : %s", rc, snippet
            )

            if not self._is_retryable(rc, stderr):
                raise MorpheExecutionError(
                    f"Morphe CLI a échoué avec le code {rc}",
                    returncode=rc,
                    stderr=stderr,
                )

            last_error = MorpheExecutionError(
                f"Morphe CLI a échoué avec le code {rc}",
                returncode=rc,
                stderr=stderr,
            )

            if attempt < request.retries:
                delay = min(
                    request.retry_delay * (2 ** (attempt - 1)),
                    MAX_RETRY_DELAY,
                )
                time.sleep(delay)

        if last_error is not None:
            raise last_error
        raise MorpheExecutionError("Échec inattendu de Morphe CLI")

    @staticmethod
    def _is_retryable(returncode: int, stderr: str) -> bool:
        if returncode in (0,):
            return False
        if returncode == 1:
            return True
        lowered = stderr.lower()
        if "out of memory" in lowered or "oom" in lowered:
            return True
        if "temporarily unavailable" in lowered:
            return True
        if "connection reset" in lowered:
            return True
        if "timeout" in lowered:
            return True
        return returncode >= 124

    def list_patches(self, mpp: Path, timeout: int = 300) -> List[Dict[str, Any]]:
        self._validate_jar()
        if not mpp.exists():
            raise ConfigurationError(f"Fichier .mpp introuvable : {mpp}")

        cmd = [
            self.java, "-jar", str(self.morphe_jar),
            "list-patches", "--patches", str(mpp),
        ]

        rc, stdout, stderr, _ = self._run_once(cmd, timeout)
        if rc != 0:
            raise MorpheExecutionError(
                f"list-patches a échoué (code {rc})",
                returncode=rc,
                stderr=stderr,
            )

        patches: List[Dict[str, Any]] = []
        for line in stdout.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            patches.append({"raw": stripped})
        return patches

    def build_request_from_config(
        self,
        apk_path: Path,
        output_path: Path,
        patches_mpp: Optional[Path] = None,
        arch: Optional[str] = None,
    ) -> PatchRequest:
        cfg = self.config
        build = cfg.get("build", {}) if isinstance(cfg.get("build"), dict) else {}
        policy = cfg.get("patchPolicy", {}) if isinstance(cfg.get("patchPolicy"), dict) else {}
        patch_options_raw = cfg.get("patchOptions", {})
        patch_options: Dict[str, Any] = {}

        if isinstance(patch_options_raw, dict):
            for key, value in patch_options_raw.items():
                if isinstance(value, dict) and "enabled" in value:
                    if value.get("enabled"):
                        for sub_key, sub_value in value.items():
                            if sub_key == "enabled":
                                continue
                            patch_options[sub_key] = sub_value

        excludes = cfg.get("excludedPatches", [])
        if not isinstance(excludes, list):
            excludes = []

        architectures: List[str] = []
        if arch is not None:
            architectures = [_normalize_architecture(arch)]
        elif isinstance(build.get("architecture"), str):
            architectures = [_normalize_architecture(build["architecture"])]

        options_file: Optional[Path] = None
        if patch_options and patches_mpp is not None:
            options_file = output_path.parent / f"{output_path.stem}_options.json"
            try:
                options_file.parent.mkdir(parents=True, exist_ok=True)
                tmp = options_file.with_suffix(".tmp")
                with tmp.open("w", encoding="utf-8") as fh:
                    json.dump(patch_options, fh, indent=2, ensure_ascii=False)
                os.replace(tmp, options_file)
            except OSError as exc:
                raise ConfigurationError(
                    f"Écriture des options de patch impossible : {exc}"
                ) from exc

        keystore = self.keystore if self.keystore.exists() else None
        keystore_password = os.environ.get("KEYSTORE_PASSWORD") or DEFAULT_KEYSTORE_PASSWORD
        keystore_alias = os.environ.get("KEYSTORE_ALIAS") or DEFAULT_KEYSTORE_ALIAS
        keystore_entry_password = os.environ.get("KEY_PASSWORD") or keystore_password

        return PatchRequest(
            apk_path=apk_path,
            output_path=output_path,
            patches_mpp=patches_mpp,
            include_patches=[],
            exclude_patches=[str(x) for x in excludes if isinstance(x, str)],
            patch_options={},
            options_file=options_file,
            keystore=keystore,
            keystore_password=keystore_password,
            keystore_alias=keystore_alias,
            keystore_entry_password=keystore_entry_password,
            strip_architectures=architectures,
            bytecode_mode="STRIP_SAFE" if bool(build.get("stripNativeLibs")) else None,
            force=bool(policy.get("failOnMissingDependency", False)) is False,
            unsigned=False,
            continue_on_error=bool(policy.get("skipIncompatible", True)),
            disable_purge=False,
            prerelease=False,
            timeout=DEFAULT_TIMEOUT_SECONDS,
            retries=int(policy.get("maxRetries", DEFAULT_RETRY_ATTEMPTS)),
            retry_delay=float(policy.get("retryDelaySeconds", DEFAULT_RETRY_DELAY)),
        )

def _build_cli_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="patcher_core",
        description="Patch un APK via Morphe CLI en utilisant la configuration du projet.",
    )
    parser.add_argument("apk", type=Path, help="APK source à patcher")
    parser.add_argument("--output", type=Path, required=True, help="Chemin de sortie de l'APK patché")
    parser.add_argument("--mpp", type=Path, default=None, help="Fichier .mpp de patches")
    parser.add_argument("--arch", default=None, help="Architecture cible (arm64-v8a, armeabi-v7a, x86, x86_64)")
    parser.add_argument("--morphe-jar", type=Path, default=DEFAULT_MORPHE_JAR, help="Chemin du JAR Morphe CLI")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH, help="Fichier de configuration JSON")
    parser.add_argument("--whitelist", type=Path, default=DEFAULT_WHITELIST_PATH, help="Liste blanche des patches")
    parser.add_argument("--keystore", type=Path, default=DEFAULT_KEYSTORE, help="Keystore de signature")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"])
    return parser

def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_cli_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

    try:
        patcher = MorphePatcher(
            morphe_jar=args.morphe_jar,
            config_path=args.config,
            whitelist_path=args.whitelist,
            keystore=args.keystore,
        )
        request = patcher.build_request_from_config(
            apk_path=args.apk,
            output_path=args.output,
            patches_mpp=args.mpp,
            arch=args.arch,
        )
        result = patcher.patch(request)
    except PatcherError as exc:
        LOGGER.error("Échec du patch : %s", exc)
        sys.stderr.write(f"patcher_core: {exc}\n")
        return 2
    except Exception:
        LOGGER.exception("Erreur inattendue lors du patch")
        sys.stderr.write("patcher_core: erreur inattendue\n")
        return 3

    sys.stdout.write(json.dumps({
        "success": result.success,
        "output": str(result.output_path) if result.output_path else None,
        "returncode": result.returncode,
        "duration_seconds": round(result.duration_seconds, 3),
        "attempts": result.attempts,
        "report": str(result.report_path) if result.report_path else None,
    }, ensure_ascii=False))
    sys.stdout.write("\n")
    return 0 if result.success else 1

if __name__ == "__main__":
    sys.exit(main())
