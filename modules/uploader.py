from __future__ import annotations

import argparse
import hashlib
import json
import logging
import mimetypes
import os
import shutil
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple
from urllib.parse import quote

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError as exc:
    raise SystemExit(
        "Le module 'requests' est requis. Installez-le via pip install requests."
    ) from exc

LOGGER = logging.getLogger("uploader")
LOGGER.addHandler(logging.NullHandler())

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DOWNLOAD_DIR = PROJECT_ROOT / "data" / "input"
DEFAULT_UPLOAD_DIR = PROJECT_ROOT / "data" / "output"
DEFAULT_LOG_DIR = PROJECT_ROOT / "data" / "logs"

TRANSFER_SH_BASE = "https://transfer.sh"
PIXELDRAIN_BASE = "https://pixeldrain.com/api"
PIXELDRAIN_KEY_ENV = "PIXELDRAIN_API_KEY"

TELEGRAM_MAX_BOT_UPLOAD = 50 * 1024 * 1024
TRANSFER_SH_MAX_FILE = 10 * 1024 * 1024 * 1024
PIXELDRAIN_FREE_MAX = 10 * 1024 * 1024 * 1024

DEFAULT_CONNECT_TIMEOUT = 30
DEFAULT_READ_TIMEOUT = 900
DEFAULT_UPLOAD_TIMEOUT = 1800
DEFAULT_RETRY_TOTAL = 3
DEFAULT_RETRY_BACKOFF = 2.0
DEFAULT_RETRY_STATUS = (429, 500, 502, 503, 504)

CHUNK_SIZE = 1024 * 1024
MAX_URL_LENGTH = 2048

ALLOWED_SCHEMES: Tuple[str, ...] = ("http", "https")
BLOCKED_HOSTS: Tuple[str, ...] = (
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "::1",
    "169.254.",
    "10.",
    "192.168.",
    "172.16.",
    "172.17.",
    "172.18.",
    "172.19.",
    "172.20.",
    "172.21.",
    "172.22.",
    "172.23.",
    "172.24.",
    "172.25.",
    "172.26.",
    "172.27.",
    "172.28.",
    "172.29.",
    "172.30.",
    "172.31.",
)

class UploaderError(Exception):
    pass

class UploaderConfigurationError(UploaderError):
    pass

class UploadFailedError(UploaderError):
    def __init__(self, message: str, status_code: Optional[int] = None, response: str = "") -> None:
        super().__init__(message)
        self.status_code = status_code
        self.response = response

class DownloadFailedError(UploaderError):
    def __init__(self, message: str, status_code: Optional[int] = None, response: str = "") -> None:
        super().__init__(message)
        self.status_code = status_code
        self.response = response

class UrlValidationError(UploaderError):
    pass

@dataclass
class UploadRequest:
    file_path: Path
    service: str = "transfer_sh"
    filename: Optional[str] = None
    max_days: Optional[int] = None
    max_downloads: Optional[int] = None
    api_key: Optional[str] = None
    timeout: int = DEFAULT_UPLOAD_TIMEOUT
    retries: int = DEFAULT_RETRY_TOTAL
    retry_backoff: float = DEFAULT_RETRY_BACKOFF

@dataclass
class UploadResult:
    success: bool
    service: str
    file_path: str
    filename: str
    size_bytes: int
    sha256: str
    download_url: Optional[str] = None
    delete_url: Optional[str] = None
    file_id: Optional[str] = None
    duration_seconds: float = 0.0
    attempts: int = 1
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

@dataclass
class DownloadRequest:
    url: str
    output_path: Path
    expected_sha256: Optional[str] = None
    timeout: int = DEFAULT_UPLOAD_TIMEOUT
    retries: int = DEFAULT_RETRY_TOTAL
    retry_backoff: float = DEFAULT_RETRY_BACKOFF
    allow_redirects: bool = True
    user_agent: str = "BOTS-Uploader/1.0"

@dataclass
class DownloadResult:
    success: bool
    url: str
    output_path: str
    size_bytes: int
    sha256: str
    duration_seconds: float = 0.0
    attempts: int = 1
    content_type: Optional[str] = None
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

def _validate_file(path: Path, max_size: Optional[int] = None) -> None:
    if not path.exists():
        raise UploaderConfigurationError(f"Fichier introuvable : {path}")
    if not path.is_file():
        raise UploaderConfigurationError(f"Chemin non régulier : {path}")
    size = path.stat().st_size
    if size == 0:
        raise UploaderConfigurationError(f"Fichier vide : {path}")
    if max_size is not None and size > max_size:
        raise UploaderConfigurationError(
            f"Fichier trop volumineux ({size} octets > {max_size})"
        )

def _validate_url(url: str) -> None:
    if not isinstance(url, str) or not url:
        raise UrlValidationError("URL vide ou invalide")
    if len(url) > MAX_URL_LENGTH:
        raise UrlValidationError(f"URL trop longue ({len(url)} > {MAX_URL_LENGTH})")
    if "://" not in url:
        raise UrlValidationError("URL sans schéma explicite")
    scheme = url.split("://", 1)[0].lower()
    if scheme not in ALLOWED_SCHEMES:
        raise UrlValidationError(f"Schéma non autorisé : {scheme!r}")
    host_part = url.split("://", 1)[1].split("/", 1)[0].split("@")[-1]
    host = host_part.split(":")[0].lower()
    if not host:
        raise UrlValidationError("Hôte absent dans l'URL")
    for blocked in BLOCKED_HOSTS:
        if host == blocked or host.startswith(blocked):
            raise UrlValidationError(
                f"Hôte bloqué pour raisons de sécurité : {host}"
            )

def _sha256_file(path: Path, chunk_size: int = CHUNK_SIZE) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(chunk_size), b""):
            h.update(chunk)
    return h.hexdigest()

def _build_session(
    retries: int,
    backoff: float,
    status_forcelist: Sequence[int],
) -> requests.Session:
    session = requests.Session()
    retry = Retry(
        total=retries,
        backoff_factor=backoff,
        status_forcelist=status_forcelist,
        allowed_methods=frozenset(["GET", "PUT", "POST", "HEAD"]),
        raise_on_status=False,
        respect_retry_after_header=True,
    )
    adapter = HTTPAdapter(max_retries=retry, pool_connections=4, pool_maxsize=8)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.headers.update({"User-Agent": "BOTS-Uploader/1.0"})
    return session

def _sanitize_filename(name: str) -> str:
    cleaned = "".join(c for c in name if c.isalnum() or c in "._-")
    if not cleaned:
        cleaned = "file"
    if len(cleaned) > 200:
        base, _, ext = cleaned.rpartition(".")
        if base and ext:
            cleaned = base[:190] + "." + ext
        else:
            cleaned = cleaned[:200]
    return cleaned

def _upload_transfer_sh(
    session: requests.Session,
    file_path: Path,
    filename: str,
    max_days: Optional[int],
    max_downloads: Optional[int],
    timeout: int,
) -> UploadResult:
    url = f"{TRANSFER_SH_BASE}/{quote(filename, safe='')}"
    headers: Dict[str, str] = {}
    if max_days is not None:
        headers["Max-Days"] = str(int(max_days))
    if max_downloads is not None:
        headers["Max-Downloads"] = str(int(max_downloads))

    file_size = file_path.stat().st_size
    sha256 = _sha256_file(file_path)

    start = time.monotonic()
    try:
        with file_path.open("rb") as fh:
            response = session.put(
                url,
                data=fh,
                headers=headers,
                timeout=(DEFAULT_CONNECT_TIMEOUT, timeout),
            )
    except requests.RequestException as exc:
        raise UploadFailedError(
            f"Erreur réseau lors de l'upload transfer.sh : {exc}"
        ) from exc

    duration = time.monotonic() - start

    if response.status_code != 200:
        snippet = (response.text or "")[:500]
        raise UploadFailedError(
            f"transfer.sh a retourné un code {response.status_code}",
            status_code=response.status_code,
            response=snippet,
        )

    download_url = (response.text or "").strip()
    if not download_url.startswith("http"):
        raise UploadFailedError(
            f"Réponse transfer.sh invalide : {download_url[:200]!r}"
        )

    delete_url = response.headers.get("X-Url-Delete") or None

    return UploadResult(
        success=True,
        service="transfer_sh",
        file_path=str(file_path),
        filename=filename,
        size_bytes=file_size,
        sha256=sha256,
        download_url=download_url,
        delete_url=delete_url,
        duration_seconds=round(duration, 3),
    )

def _upload_pixeldrain(
    session: requests.Session,
    file_path: Path,
    filename: str,
    api_key: Optional[str],
    timeout: int,
) -> UploadResult:
    url = f"{PIXELDRAIN_BASE}/file/{quote(filename, safe='')}"
    headers: Dict[str, str] = {}
    if api_key:
        headers["Authorization"] = f"Basic {_b64(f':{api_key}')}"

    file_size = file_path.stat().st_size
    sha256 = _sha256_file(file_path)

    start = time.monotonic()
    try:
        with file_path.open("rb") as fh:
            response = session.put(
                url,
                data=fh,
                headers=headers,
                timeout=(DEFAULT_CONNECT_TIMEOUT, timeout),
            )
    except requests.RequestException as exc:
        raise UploadFailedError(
            f"Erreur réseau lors de l'upload PixelDrain : {exc}"
        ) from exc

    duration = time.monotonic() - start

    if response.status_code != 200:
        snippet = (response.text or "")[:500]
        raise UploadFailedError(
            f"PixelDrain a retourné un code {response.status_code}",
            status_code=response.status_code,
            response=snippet,
        )

    try:
        payload = response.json()
    except ValueError as exc:
        raise UploadFailedError(
            "PixelDrain n'a pas retourné un JSON valide",
            status_code=response.status_code,
            response=(response.text or "")[:500],
        ) from exc

    if not isinstance(payload, dict) or not payload.get("success"):
        raise UploadFailedError(
            "PixelDrain a signalé un échec d'upload",
            status_code=response.status_code,
            response=json.dumps(payload)[:500],
        )

    file_id = payload.get("id")
    if not isinstance(file_id, str) or not file_id:
        raise UploadFailedError(
            "PixelDrain n'a pas retourné d'identifiant de fichier",
            status_code=response.status_code,
            response=json.dumps(payload)[:500],
        )

    download_url = f"https://pixeldrain.com/u/{file_id}"

    return UploadResult(
        success=True,
        service="pixeldrain",
        file_path=str(file_path),
        filename=filename,
        size_bytes=file_size,
        sha256=sha256,
        download_url=download_url,
        file_id=file_id,
        duration_seconds=round(duration, 3),
    )

def _b64(text: str) -> str:
    import base64
    return base64.b64encode(text.encode("utf-8")).decode("ascii")

def upload_file(request: UploadRequest) -> UploadResult:
    if not isinstance(request.file_path, Path):
        request.file_path = Path(request.file_path)

    service = request.service.strip().lower()
    if service not in ("transfer_sh", "pixeldrain"):
        raise UploaderConfigurationError(
            f"Service d'upload inconnu : {service!r}"
        )

    max_size = (
        TRANSFER_SH_MAX_FILE if service == "transfer_sh" else PIXELDRAIN_FREE_MAX
    )
    _validate_file(request.file_path, max_size=max_size)

    filename = request.filename or request.file_path.name
    filename = _sanitize_filename(filename)

    api_key: Optional[str] = request.api_key
    if service == "pixeldrain" and api_key is None:
        api_key = os.environ.get(PIXELDRAIN_KEY_ENV) or None

    session = _build_session(
        retries=request.retries,
        backoff=request.retry_backoff,
        status_forcelist=DEFAULT_RETRY_STATUS,
    )

    attempts = 0
    last_error: Optional[Exception] = None

    try:
        for attempt in range(1, request.retries + 1):
            attempts = attempt
            try:
                if service == "transfer_sh":
                    result = _upload_transfer_sh(
                        session=session,
                        file_path=request.file_path,
                        filename=filename,
                        max_days=request.max_days,
                        max_downloads=request.max_downloads,
                        timeout=request.timeout,
                    )
                else:
                    result = _upload_pixeldrain(
                        session=session,
                        file_path=request.file_path,
                        filename=filename,
                        api_key=api_key,
                        timeout=request.timeout,
                    )
                result.attempts = attempt
                return result

            except UploadFailedError as exc:
                last_error = exc
                status = exc.status_code
                if status is not None and status not in DEFAULT_RETRY_STATUS:
                    raise
                if attempt < request.retries:
                    delay = request.retry_backoff * (2 ** (attempt - 1))
                    delay = min(delay, 60.0)
                    LOGGER.warning(
                        "Tentative %d/%d échouée (%s), nouvel essai dans %.1fs",
                        attempt, request.retries, exc, delay,
                    )
                    time.sleep(delay)
    finally:
        session.close()

    if last_error is not None:
        raise last_error
    raise UploadFailedError("Échec d'upload inattendu")

def download_file(request: DownloadRequest) -> DownloadResult:
    if not isinstance(request.output_path, Path):
        request.output_path = Path(request.output_path)

    _validate_url(request.url)

    request.output_path.parent.mkdir(parents=True, exist_ok=True)

    session = _build_session(
        retries=request.retries,
        backoff=request.retry_backoff,
        status_forcelist=DEFAULT_RETRY_STATUS,
    )
    session.headers.update({"User-Agent": request.user_agent})

    tmp_path = request.output_path.with_suffix(
        request.output_path.suffix + f".tmp-{os.getpid()}"
    )

    attempts = 0
    last_error: Optional[Exception] = None

    try:
        for attempt in range(1, request.retries + 1):
            attempts = attempt
            try:
                start = time.monotonic()
                with session.get(
                    request.url,
                    stream=True,
                    timeout=(DEFAULT_CONNECT_TIMEOUT, request.timeout),
                    allow_redirects=request.allow_redirects,
                ) as response:
                    if response.status_code != 200:
                        snippet = (response.text or "")[:500]
                        raise DownloadFailedError(
                            f"Téléchargement échoué (code {response.status_code})",
                            status_code=response.status_code,
                            response=snippet,
                        )

                    content_length = response.headers.get("Content-Length")
                    content_type = response.headers.get("Content-Type")

                    h = hashlib.sha256()
                    written = 0
                    with tmp_path.open("wb") as fh:
                        for chunk in response.iter_content(chunk_size=CHUNK_SIZE):
                            if not chunk:
                                continue
                            fh.write(chunk)
                            h.update(chunk)
                            written += len(chunk)

                    if content_length is not None:
                        try:
                            expected = int(content_length)
                            if written != expected:
                                raise DownloadFailedError(
                                    f"Taille téléchargée incohérente "
                                    f"({written} != {expected})"
                                )
                        except ValueError:
                            LOGGER.debug("Content-Length non numérique : %s", content_length)

                duration = time.monotonic() - start
                sha256 = h.hexdigest()

                if written < 1024:
                    raise DownloadFailedError(
                        f"Fichier téléchargé trop petit ({written} octets)"
                    )

                if request.expected_sha256:
                    expected = request.expected_sha256.lower().strip()
                    if sha256 != expected:
                        raise DownloadFailedError(
                            "SHA-256 incohérent : "
                            f"attendu {expected[:16]}..., obtenu {sha256[:16]}..."
                        )

                try:
                    os.replace(tmp_path, request.output_path)
                except OSError as exc:
                    raise DownloadFailedError(
                        f"Finalisation du téléchargement impossible : {exc}"
                    ) from exc

                return DownloadResult(
                    success=True,
                    url=request.url,
                    output_path=str(request.output_path),
                    size_bytes=written,
                    sha256=sha256,
                    duration_seconds=round(duration, 3),
                    attempts=attempt,
                    content_type=content_type,
                )

            except DownloadFailedError as exc:
                last_error = exc
                _safe_unlink(tmp_path)
                status = exc.status_code
                if status is not None and status not in DEFAULT_RETRY_STATUS:
                    raise
                if attempt < request.retries:
                    delay = request.retry_backoff * (2 ** (attempt - 1))
                    delay = min(delay, 60.0)
                    LOGGER.warning(
                        "Tentative %d/%d échouée (%s), nouvel essai dans %.1fs",
                        attempt, request.retries, exc, delay,
                    )
                    time.sleep(delay)
    finally:
        session.close()
        _safe_unlink(tmp_path)

    if last_error is not None:
        raise last_error
    raise DownloadFailedError("Échec de téléchargement inattendu")

def _safe_unlink(path: Path) -> None:
    try:
        if path.exists():
            path.unlink()
    except OSError:
        LOGGER.debug("Suppression impossible : %s", path)

def needs_external_upload(file_path: Path) -> bool:
    try:
        size = file_path.stat().st_size
    except OSError:
        return True
    return size > TELEGRAM_MAX_BOT_UPLOAD

def _build_cli_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="uploader",
        description=(
            "Télécharge ou envoie des fichiers vers un service de partage "
            "temporaire (transfer.sh, PixelDrain)."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    up = sub.add_parser("upload", help="Envoyer un fichier")
    up.add_argument("file", type=Path)
    up.add_argument(
        "--service",
        default="transfer_sh",
        choices=["transfer_sh", "pixeldrain"],
    )
    up.add_argument("--filename", default=None)
    up.add_argument("--max-days", type=int, default=None)
    up.add_argument("--max-downloads", type=int, default=None)
    up.add_argument("--timeout", type=int, default=DEFAULT_UPLOAD_TIMEOUT)
    up.add_argument("--retries", type=int, default=DEFAULT_RETRY_TOTAL)
    up.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
    )

    down = sub.add_parser("download", help="Télécharger un fichier")
    down.add_argument("url")
    down.add_argument("output", type=Path)
    down.add_argument("--sha256", default=None)
    down.add_argument("--timeout", type=int, default=DEFAULT_UPLOAD_TIMEOUT)
    down.add_argument("--retries", type=int, default=DEFAULT_RETRY_TOTAL)
    down.add_argument(
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

    try:
        if args.command == "upload":
            request = UploadRequest(
                file_path=args.file,
                service=args.service,
                filename=args.filename,
                max_days=args.max_days,
                max_downloads=args.max_downloads,
                timeout=args.timeout,
                retries=args.retries,
            )
            result = upload_file(request)
        elif args.command == "download":
            request = DownloadRequest(
                url=args.url,
                output_path=args.output,
                expected_sha256=args.sha256,
                timeout=args.timeout,
                retries=args.retries,
            )
            result = download_file(request)
        else:
            parser.error(f"Commande inconnue : {args.command}")
            return 2
    except UploaderConfigurationError as exc:
        LOGGER.error("Configuration invalide : %s", exc)
        sys.stderr.write(f"uploader: {exc}\n")
        return 2
    except UrlValidationError as exc:
        LOGGER.error("URL invalide : %s", exc)
        sys.stderr.write(f"uploader: {exc}\n")
        return 3
    except (UploadFailedError, DownloadFailedError) as exc:
        LOGGER.error("Opération échouée : %s", exc)
        sys.stderr.write(f"uploader: {exc}\n")
        return 4
    except Exception:
        LOGGER.exception("Erreur inattendue")
        sys.stderr.write("uploader: erreur inattendue\n")
        return 5

    payload = asdict(result)
    serialized = json.dumps(payload, ensure_ascii=False, indent=2)
    sys.stdout.write(serialized)
    sys.stdout.write("\n")

    return 0 if result.success else 1

if __name__ == "__main__":
    sys.exit(main())
