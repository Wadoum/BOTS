from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import re
import signal
import sys
import tempfile
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Deque, Dict, Optional, Set, Tuple

try:
    import requests
except ImportError as exc:
    raise SystemExit(
        "Le module 'requests' est requis. Installez-le via pip install requests."
    ) from exc

try:
    from telegram import BotCommand, Update
    from telegram.constants import ChatAction
    from telegram.error import (
        BadRequest,
        Forbidden,
        NetworkError,
        RetryAfter,
        TelegramError,
    )
    from telegram.ext import (
        Application,
        ApplicationBuilder,
        CommandHandler,
        ContextTypes,
        MessageHandler,
        filters,
    )
except ImportError as exc:
    raise SystemExit(
        "Le module 'python-telegram-bot' est requis (>=21.6)."
    ) from exc

from modules.uploader import (
    UploadFailedError,
    UploadRequest,
    UploaderConfigurationError,
    UploaderError,
    UrlValidationError,
    upload_file,
)

LOGGER = logging.getLogger("bot")
LOGGER.addHandler(logging.NullHandler())

PROJECT_ROOT = Path(__file__).resolve().parent
DATA_DIR = PROJECT_ROOT / "data"
TMP_DIR = DATA_DIR / "tmp"
LOG_DIR = DATA_DIR / "logs"

TELEGRAM_TOKEN_ENV = "TELEGRAM_TOKEN"
GH_PAT_ENV = "GH_PAT"
GH_REPO_ENV = "GH_REPO"
GH_WORKFLOW_ENV = "GH_WORKFLOW_FILE"
GH_REF_ENV = "GH_REF"

DEFAULT_GH_REPO = "Wadoum/BOTS"
DEFAULT_GH_WORKFLOW = "patcher.yml"
DEFAULT_GH_REF = "main"

MAX_TELEGRAM_DOWNLOAD = 20 * 1024 * 1024
MAX_INPUT_FILE_SIZE = 500 * 1024 * 1024
TELEGRAM_CAPTION_LIMIT = 1024
TELEGRAM_TEXT_LIMIT = 4096

RATE_LIMIT_WINDOW_SECONDS = 3600
RATE_LIMIT_MAX_PER_WINDOW = 5
RATE_LIMIT_MAX_CONCURRENT = 2

DEDUP_WINDOW_SECONDS = 300
DEDUP_MAX_ENTRIES = 500

GITHUB_API_BASE = "https://api.github.com"
GITHUB_API_VERSION = "2022-11-28"
GITHUB_TIMEOUT = 30
GITHUB_RETRY_ATTEMPTS = 3
GITHUB_RETRY_BACKOFF = 2.0

ALLOWED_ARCHITECTURES: Tuple[str, ...] = (
    "arm64-v8a",
    "armeabi-v7a",
    "x86_64",
)
DEFAULT_ARCHITECTURE = "arm64-v8a"

APK_MAGIC = b"PK\x03\x04"
APK_EXTENSIONS: Tuple[str, ...] = (".apk", ".apks", ".apkm", ".xapk")

URL_PATTERN = re.compile(
    r"^https?://[^\s]+$",
    re.IGNORECASE,
)

class BotError(Exception):
    pass

class BotConfigurationError(BotError):
    pass

class RateLimitExceeded(BotError):
    def __init__(self, retry_after: float) -> None:
        super().__init__(f"Limite de débit dépassée, réessayez dans {retry_after:.0f}s")
        self.retry_after = retry_after

class DuplicateSubmission(BotError):
    pass

class WorkflowDispatchError(BotError):
    def __init__(self, message: str, status_code: Optional[int] = None, detail: str = "") -> None:
        super().__init__(message)
        self.status_code = status_code
        self.detail = detail

@dataclass
class BotConfig:
    telegram_token: str
    gh_pat: str
    gh_repo: str
    gh_workflow_file: str
    gh_ref: str

    @classmethod
    def from_env(cls) -> "BotConfig":
        token = os.environ.get(TELEGRAM_TOKEN_ENV, "").strip()
        if not token:
            raise BotConfigurationError(
                f"Variable d'environnement {TELEGRAM_TOKEN_ENV} manquante"
            )
        if not re.match(r"^\d{6,}:[A-Za-z0-9_-]{30,}$", token):
            raise BotConfigurationError(
                f"Format du token Telegram invalide ({TELEGRAM_TOKEN_ENV})"
            )

        pat = os.environ.get(GH_PAT_ENV, "").strip()
        if not pat:
            raise BotConfigurationError(
                f"Variable d'environnement {GH_PAT_ENV} manquante "
                "(Personal Access Token GitHub requis)"
            )

        repo = os.environ.get(GH_REPO_ENV, DEFAULT_GH_REPO).strip() or DEFAULT_GH_REPO
        if not re.match(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", repo):
            raise BotConfigurationError(f"GH_REPO invalide : {repo!r}")

        workflow = os.environ.get(GH_WORKFLOW_ENV, DEFAULT_GH_WORKFLOW).strip() \
            or DEFAULT_GH_WORKFLOW
        if not re.match(r"^[A-Za-z0-9_.-]+\.(yml|yaml)$", workflow):
            raise BotConfigurationError(
                f"GH_WORKFLOW_FILE invalide : {workflow!r}"
            )

        ref = os.environ.get(GH_REF_ENV, DEFAULT_GH_REF).strip() or DEFAULT_GH_REF
        if not re.match(r"^[A-Za-z0-9_.\-/]+$", ref):
            raise BotConfigurationError(f"GH_REF invalide : {ref!r}")

        return cls(
            telegram_token=token,
            gh_pat=pat,
            gh_repo=repo,
            gh_workflow_file=workflow,
            gh_ref=ref,
        )

class RateLimiter:
    def __init__(
        self,
        window_seconds: int = RATE_LIMIT_WINDOW_SECONDS,
        max_per_window: int = RATE_LIMIT_MAX_PER_WINDOW,
    ) -> None:
        self._window = window_seconds
        self._max = max_per_window
        self._buckets: Dict[int, Deque[float]] = defaultdict(deque)

    def check(self, user_id: int) -> None:
        now = time.monotonic()
        bucket = self._buckets[user_id]
        cutoff = now - self._window
        while bucket and bucket[0] < cutoff:
            bucket.popleft()
        if len(bucket) >= self._max:
            oldest = bucket[0]
            retry_after = max(1.0, self._window - (now - oldest))
            raise RateLimitExceeded(retry_after)

    def record(self, user_id: int) -> None:
        self._buckets[user_id].append(time.monotonic())

    def status(self, user_id: int) -> Tuple[int, int]:
        now = time.monotonic()
        cutoff = now - self._window
        bucket = self._buckets[user_id]
        while bucket and bucket[0] < cutoff:
            bucket.popleft()
        return len(bucket), self._max

class Deduplicator:
    def __init__(
        self,
        window_seconds: int = DEDUP_WINDOW_SECONDS,
        max_entries: int = DEDUP_MAX_ENTRIES,
    ) -> None:
        self._window = window_seconds
        self._max = max_entries
        self._entries: Dict[str, float] = {}

    def _gc(self, now: float) -> None:
        cutoff = now - self._window
        stale = [k for k, ts in self._entries.items() if ts < cutoff]
        for k in stale:
            self._entries.pop(k, None)
        if len(self._entries) > self._max:
            sorted_items = sorted(self._entries.items(), key=lambda kv: kv[1])
            for k, _ in sorted_items[: len(sorted_items) - self._max]:
                self._entries.pop(k, None)

    def check_and_record(self, user_id: int, file_hash: str) -> None:
        now = time.monotonic()
        self._gc(now)
        key = f"{user_id}:{file_hash}"
        if key in self._entries:
            raise DuplicateSubmission(
                "Ce fichier a déjà été soumis récemment. "
                "Attendez quelques minutes ou renommez-le."
            )
        self._entries[key] = now

class GitHubDispatcher:
    def __init__(
        self,
        pat: str,
        repo: str,
        workflow_file: str,
        ref: str,
        timeout: int = GITHUB_TIMEOUT,
        retries: int = GITHUB_RETRY_ATTEMPTS,
        retry_backoff: float = GITHUB_RETRY_BACKOFF,
    ) -> None:
        self._pat = pat
        self._repo = repo
        self._workflow_file = workflow_file
        self._ref = ref
        self._timeout = timeout
        self._retries = max(1, retries)
        self._retry_backoff = retry_backoff
        self._session = requests.Session()
        self._session.headers.update({
            "Authorization": f"Bearer {self._pat}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": GITHUB_API_VERSION,
            "User-Agent": "BOTS-Telegram-Bot/1.0",
        })

    def close(self) -> None:
        try:
            self._session.close()
        except Exception:  # noqa: BLE001
            LOGGER.debug("Fermeture de session GitHub échouée", exc_info=True)

    def dispatch(
        self,
        file_url: str,
        user_id: int,
        chat_id: int,
        file_name: str,
        arch: str,
    ) -> Dict[str, Any]:
        url = (
            f"{GITHUB_API_BASE}/repos/{self._repo}"
            f"/actions/workflows/{self._workflow_file}/dispatches"
        )
        payload = {
            "ref": self._ref,
            "inputs": {
                "file_url": file_url,
                "user_id": str(user_id),
                "chat_id": str(chat_id),
                "file_name": file_name,
                "arch": arch,
            },
        }

        last_exc: Optional[Exception] = None
        for attempt in range(1, self._retries + 1):
            try:
                response = self._session.post(
                    url,
                    json=payload,
                    timeout=self._timeout,
                )
            except requests.RequestException as exc:
                last_exc = exc
                LOGGER.warning(
                    "Erreur réseau GitHub (tentative %d/%d) : %s",
                    attempt, self._retries, exc,
                )
                if attempt < self._retries:
                    delay = self._retry_backoff * (2 ** (attempt - 1))
                    time.sleep(min(delay, 30.0))
                    continue
                raise WorkflowDispatchError(
                    f"Erreur réseau GitHub : {exc}"
                ) from exc

            if response.status_code == 204:
                return {"status": "dispatched", "run_url": self._runs_url()}

            if response.status_code in (401, 403):
                raise WorkflowDispatchError(
                    "Authentification GitHub refusée "
                    "(vérifiez le token GH_PAT et ses scopes)",
                    status_code=response.status_code,
                    detail=(response.text or "")[:500],
                )

            if response.status_code == 404:
                raise WorkflowDispatchError(
                    f"Dépôt ou workflow introuvable : "
                    f"{self._repo}/{self._workflow_file}",
                    status_code=response.status_code,
                    detail=(response.text or "")[:500],
                )

            if response.status_code == 422:
                raise WorkflowDispatchError(
                    "Payload de dispatch rejeté par GitHub "
                    "(vérifiez les inputs du workflow)",
                    status_code=response.status_code,
                    detail=(response.text or "")[:500],
                )

            if response.status_code in (429, 500, 502, 503, 504) \
                    and attempt < self._retries:
                delay = self._retry_backoff * (2 ** (attempt - 1))
                LOGGER.warning(
                    "GitHub a retourné %d (tentative %d/%d), attente %.1fs",
                    response.status_code, attempt, self._retries, delay,
                )
                time.sleep(min(delay, 30.0))
                continue

            raise WorkflowDispatchError(
                f"GitHub a retourné un code {response.status_code}",
                status_code=response.status_code,
                detail=(response.text or "")[:500],
            )

        if last_exc is not None:
            raise WorkflowDispatchError(f"Échec du dispatch : {last_exc}")
        raise WorkflowDispatchError("Échec du dispatch inattendu")

    def _runs_url(self) -> str:
        return (
            f"https://github.com/{self._repo}/actions/workflows/"
            f"{self._workflow_file}"
        )

def _ensure_directories() -> None:
    for d in (DATA_DIR, TMP_DIR, LOG_DIR):
        try:
            d.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise BotConfigurationError(
                f"Création du répertoire {d} impossible : {exc}"
            ) from exc

def _setup_logging(level: str = "INFO") -> None:
    root = logging.getLogger()
    for h in list(root.handlers):
        root.removeHandler(h)

    formatter = logging.Formatter(
        fmt="%(asctime)s %(levelname)s %(name)s %(message)s"
    )

    stream_handler = logging.StreamHandler(sys.stderr)
    stream_handler.setFormatter(formatter)
    root.addHandler(stream_handler)

    log_file = LOG_DIR / "bot.log"
    try:
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setFormatter(formatter)
        root.addHandler(file_handler)
    except OSError:
        LOGGER.warning("Impossible d'ouvrir le fichier de log %s", log_file)

    root.setLevel(getattr(logging, level.upper(), logging.INFO))

def _sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(chunk_size), b""):
            h.update(chunk)
    return h.hexdigest()

def _sanitize_filename(name: str) -> str:
    base = Path(name).name
    cleaned = "".join(c for c in base if c.isalnum() or c in "._-")
    if not cleaned:
        cleaned = "application.apk"
    if len(cleaned) > 200:
        stem, dot, ext = cleaned.rpartition(".")
        if stem and dot:
            cleaned = stem[:190] + "." + ext
        else:
            cleaned = cleaned[:200]
    return cleaned

def _is_apk_filename(name: str) -> bool:
    lower = name.lower()
    return any(lower.endswith(ext) for ext in APK_EXTENSIONS)

def _verify_apk_magic(path: Path) -> None:
    if not path.exists():
        raise BotError(f"Fichier introuvable : {path}")
    size = path.stat().st_size
    if size < 1024:
        raise BotError(f"Fichier trop petit ({size} octets)")
    if size > MAX_INPUT_FILE_SIZE:
        raise BotError(
            f"Fichier trop volumineux ({size} > {MAX_INPUT_FILE_SIZE})"
        )
    try:
        with path.open("rb") as fh:
            header = fh.read(4)
    except OSError as exc:
        raise BotError(f"Lecture impossible : {exc}") from exc
    if header[:2] != APK_MAGIC[:2]:
        raise BotError(
            "Le fichier ne semble pas être un APK/ZIP valide "
            "(signature manquante)"
        )

def _safe_text_reply(message: str, limit: int = TELEGRAM_TEXT_LIMIT) -> str:
    if len(message) <= limit:
        return message
    return message[: limit - 20] + "\n\n[...]"

async def _run_in_executor(func, *args, **kwargs):
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(
        None,
        lambda: func(*args, **kwargs),
    )

async def _safe_send(
    context: ContextTypes.DEFAULT_TYPE,
    chat_id: int,
    text: str,
    reply_to: Optional[int] = None,
) -> None:
    try:
        await context.bot.send_message(
            chat_id=chat_id,
            text=_safe_text_reply(text),
            reply_to_message_id=reply_to,
            disable_web_page_preview=True,
        )
    except RetryAfter as exc:
        await asyncio.sleep(float(exc.retry_after) + 1.0)
        try:
            await context.bot.send_message(
                chat_id=chat_id,
                text=_safe_text_reply(text),
                disable_web_page_preview=True,
            )
        except TelegramError as inner:
            LOGGER.error("Envoi Telegram impossible après retry : %s", inner)
    except Forbidden:
        LOGGER.warning("Bot bloqué par l'utilisateur (chat %s)", chat_id)
    except TelegramError as exc:
        LOGGER.error("Erreur d'envoi Telegram : %s", exc)

async def _safe_action(
    context: ContextTypes.DEFAULT_TYPE,
    chat_id: int,
    action: str = ChatAction.TYPING,
) -> None:
    try:
        await context.bot.send_chat_action(chat_id=chat_id, action=action)
    except TelegramError:
        pass

async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.effective_chat is None or update.effective_user is None:
        return

    text = (
        "Bienvenue sur le patcheur d'APK.\n\n"
        "Envoyez-moi un fichier APK (< 20 Mo) ou un lien direct HTTPS "
        "vers un APK à patcher, et je m'occupe du reste :\n"
        "  1. Téléchargement et validation\n"
        "  2. Patch automatique (Morphe CLI)\n"
        "  3. Extraction 64-bit\n"
        "  4. Signature\n"
        "  5. Envoi du résultat dans cette conversation\n\n"
        "Commandes disponibles :\n"
        "/help - afficher l'aide\n"
        "/status - état de votre quota\n"
        "/arch - choisir l'architecture cible\n\n"
        f"Architecture actuelle : {_get_arch(context)}"
    )
    await _safe_send(context, update.effective_chat.id, text)

async def cmd_help(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.effective_chat is None:
        return
    text = (
        "Utilisation du bot :\n\n"
        "• Envoyez un APK directement (max 20 Mo via Telegram).\n"
        "• Ou envoyez un lien HTTPS direct vers un APK.\n\n"
        "Le traitement peut prendre plusieurs minutes. "
        "Le résultat vous sera envoyé automatiquement.\n\n"
        "Commandes :\n"
        "/start - message d'accueil\n"
        "/help - cette aide\n"
        "/status - votre quota d'utilisation\n"
        "/arch <architecture> - choisir la cible "
        "(arm64-v8a, armeabi-v7a, x86_64)\n\n"
        f"Quota : {RATE_LIMIT_MAX_PER_WINDOW} requêtes / heure."
    )
    await _safe_send(context, update.effective_chat.id, text)

async def cmd_status(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.effective_chat is None or update.effective_user is None:
        return
    limiter: RateLimiter = context.application.bot_data["rate_limiter"]
    used, max_ = limiter.status(update.effective_user.id)
    text = (
        f"Quota : {used}/{max_} utilisés sur la dernière heure.\n"
        f"Architecture : {_get_arch(context)}\n"
        f"Traitements simultanés max : {RATE_LIMIT_MAX_CONCURRENT}"
    )
    await _safe_send(context, update.effective_chat.id, text)

async def cmd_arch(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.effective_chat is None:
        return
    args = context.args or []
    if not args:
        current = _get_arch(context)
        text = (
            f"Architecture actuelle : {current}\n"
            f"Valeurs acceptées : {', '.join(ALLOWED_ARCHITECTURES)}"
        )
        await _safe_send(context, update.effective_chat.id, text)
        return

    requested = args[0].strip().lower()
    if requested not in ALLOWED_ARCHITECTURES:
        await _safe_send(
            context,
            update.effective_chat.id,
            f"Architecture non supportée : {requested}\n"
            f"Valeurs acceptées : {', '.join(ALLOWED_ARCHITECTURES)}",
        )
        return

    context.user_data["arch"] = requested
    await _safe_send(
        context,
        update.effective_chat.id,
        f"Architecture définie sur : {requested}",
    )

def _get_arch(context: ContextTypes.DEFAULT_TYPE) -> str:
    arch = context.user_data.get("arch") if context.user_data else None
    if isinstance(arch, str) and arch in ALLOWED_ARCHITECTURES:
        return arch
    return DEFAULT_ARCHITECTURE

async def on_document(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.effective_chat is None or update.effective_user is None:
        return
    message = update.effective_message
    if message is None or message.document is None:
        return

    document = message.document
    user_id = update.effective_user.id
    chat_id = update.effective_chat.id

    if not _is_apk_filename(document.file_name or ""):
        await _safe_send(
            context, chat_id,
            "Le fichier envoyé ne semble pas être un APK "
            f"(extensions acceptées : {', '.join(APK_EXTENSIONS)}).",
            reply_to=message.message_id,
        )
        return

    file_size = document.file_size or 0
    if file_size > MAX_TELEGRAM_DOWNLOAD:
        await _safe_send(
            context, chat_id,
            f"Le fichier dépasse la limite de téléchargement Telegram "
            f"({file_size} octets > {MAX_TELEGRAM_DOWNLOAD} octets).\n"
            "Hébergez-le ailleurs et envoyez-moi un lien HTTPS direct.",
            reply_to=message.message_id,
        )
        return

    limiter: RateLimiter = context.application.bot_data["rate_limiter"]
    try:
        limiter.check(user_id)
    except RateLimitExceeded as exc:
        await _safe_send(
            context, chat_id,
            f"Quota atteint. Réessayez dans {exc.retry_after:.0f} secondes.",
            reply_to=message.message_id,
        )
        return

    semaphore: asyncio.Semaphore = context.application.bot_data["semaphore"]
    if semaphore.locked():
        await _safe_send(
            context, chat_id,
            "Le service est actuellement occupé. Réessayez dans un instant.",
            reply_to=message.message_id,
        )
        return

    await _safe_action(context, chat_id, ChatAction.TYPING)
    await _safe_send(
        context, chat_id,
        "Fichier reçu. Traitement en cours…",
        reply_to=message.message_id,
    )

    async with semaphore:
        try:
            await _handle_document(
                update=update,
                context=context,
                document=document,
                user_id=user_id,
                chat_id=chat_id,
            )
        except RateLimitExceeded as exc:
            await _safe_send(
                context, chat_id,
                f"Quota atteint : {exc.retry_after:.0f}s",
            )
        except DuplicateSubmission as exc:
            await _safe_send(context, chat_id, str(exc))
        except UploaderError as exc:
            LOGGER.error("Upload impossible : %s", exc)
            await _safe_send(
                context, chat_id,
                "Échec de l'hébergement temporaire du fichier. "
                "Veuillez réessayer plus tard.",
            )
        except WorkflowDispatchError as exc:
            LOGGER.error("Dispatch GitHub échoué : %s", exc)
            await _safe_send(
                context, chat_id,
                "Le traitement distant n'a pas pu être déclenché. "
                "Veuillez réessayer plus tard.",
            )
        except BotError as exc:
            await _safe_send(context, chat_id, f"Erreur : {exc}")
        except TelegramError as exc:
            LOGGER.error("Erreur Telegram : %s", exc)
        except Exception:
            LOGGER.exception("Erreur inattendue lors du traitement d'un document")
            await _safe_send(
                context, chat_id,
                "Erreur interne inattendue. Le traitement a été annulé.",
            )

async def _handle_document(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    document,
    user_id: int,
    chat_id: int,
) -> None:
    original_name = _sanitize_filename(document.file_name or "application.apk")
    tmp_input = TMP_DIR / f"{user_id}_{int(time.time()*1000)}_{original_name}"

    try:
        tg_file = await context.bot.get_file(document.file_id)
        await tg_file.download_to_drive(custom_path=str(tmp_input))
    except TelegramError as exc:
        LOGGER.error("Téléchargement Telegram échoué : %s", exc)
        raise BotError("Impossible de télécharger le fichier depuis Telegram.")

    try:
        _verify_apk_magic(tmp_input)
        file_hash = _sha256_file(tmp_input)

        dedup: Deduplicator = context.application.bot_data["deduplicator"]
        dedup.check_and_record(user_id, file_hash)

        file_url = await _upload_to_transfer_sh(tmp_input)

        dispatcher: GitHubDispatcher = context.application.bot_data["dispatcher"]
        arch = _get_arch(context)
        result = await _run_in_executor(
            dispatcher.dispatch,
            file_url,
            user_id,
            chat_id,
            original_name,
            arch,
        )

        limiter: RateLimiter = context.application.bot_data["rate_limiter"]
        limiter.record(user_id)

        runs_url = result.get("run_url") if isinstance(result, dict) else None
        text = (
            "Traitement lancé avec succès.\n"
            f"Fichier : {original_name}\n"
            f"Architecture : {arch}\n"
            f"Taille : {tmp_input.stat().st_size} octets\n\n"
            "Vous recevrez le résultat dans cette conversation dès que "
            "le pipeline est terminé."
        )
        if runs_url:
            text += f"\n\nSuivi : {runs_url}"
        await _safe_send(context, chat_id, text)

    finally:
        _safe_unlink(tmp_input)

async def on_url(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.effective_chat is None or update.effective_user is None:
        return
    message = update.effective_message
    if message is None or not message.text:
        return

    url = message.text.strip()
    if not URL_PATTERN.match(url):
        return

    user_id = update.effective_user.id
    chat_id = update.effective_chat.id

    limiter: RateLimiter = context.application.bot_data["rate_limiter"]
    try:
        limiter.check(user_id)
    except RateLimitExceeded as exc:
        await _safe_send(
            context, chat_id,
            f"Quota atteint. Réessayez dans {exc.retry_after:.0f} secondes.",
            reply_to=message.message_id,
        )
        return

    semaphore: asyncio.Semaphore = context.application.bot_data["semaphore"]
    if semaphore.locked():
        await _safe_send(
            context, chat_id,
            "Le service est actuellement occupé. Réessayez dans un instant.",
            reply_to=message.message_id,
        )
        return

    await _safe_action(context, chat_id, ChatAction.TYPING)
    await _safe_send(
        context, chat_id,
        "Lien reçu. Analyse en cours…",
        reply_to=message.message_id,
    )

    async with semaphore:
        tmp_input: Optional[Path] = None
        try:
            dispatcher: GitHubDispatcher = context.application.bot_data["dispatcher"]
            filename = _extract_filename_from_url(url)
            if not _is_apk_filename(filename):
                await _safe_send(
                    context, chat_id,
                    "Le lien ne pointe pas vers un fichier APK reconnaissable.",
                )
                return

            file_url = url
            arch = _get_arch(context)
            result = await _run_in_executor(
                dispatcher.dispatch,
                file_url,
                user_id,
                chat_id,
                filename,
                arch,
            )

            limiter.record(user_id)

            runs_url = result.get("run_url") if isinstance(result, dict) else None
            text = (
                "Traitement lancé avec succès.\n"
                f"Fichier : {filename}\n"
                f"Architecture : {arch}\n\n"
                "Vous recevrez le résultat dans cette conversation."
            )
            if runs_url:
                text += f"\n\nSuivi : {runs_url}"
            await _safe_send(context, chat_id, text)

        except WorkflowDispatchError as exc:
            LOGGER.error("Dispatch GitHub échoué : %s", exc)
            await _safe_send(
                context, chat_id,
                "Le traitement distant n'a pas pu être déclenché.",
            )
        except UrlValidationError as exc:
            await _safe_send(context, chat_id, f"URL refusée : {exc}")
        except BotError as exc:
            await _safe_send(context, chat_id, f"Erreur : {exc}")
        except Exception:
            LOGGER.exception("Erreur inattendue lors du traitement d'une URL")
            await _safe_send(
                context, chat_id,
                "Erreur interne inattendue.",
            )
        finally:
            if tmp_input is not None:
                _safe_unlink(tmp_input)

def _extract_filename_from_url(url: str) -> str:
    try:
        base = url.split("?", 1)[0].split("#", 1)[0]
        name = base.rsplit("/", 1)[-1]
        return _sanitize_filename(name) if name else "application.apk"
    except Exception:  # noqa: BLE001
        return "application.apk"

async def _upload_to_transfer_sh(path: Path) -> str:
    request = UploadRequest(
        file_path=path,
        service="transfer_sh",
        filename=_sanitize_filename(path.name),
        max_days=7,
    )
    try:
        result = await _run_in_executor(upload_file, request)
    except UploaderConfigurationError as exc:
        raise BotError(f"Configuration d'upload invalide : {exc}") from exc
    except UploadFailedError as exc:
        raise BotError(f"Upload échoué : {exc}") from exc
    except UploaderError as exc:
        raise BotError(f"Erreur d'upload : {exc}") from exc

    if not result.success or not result.download_url:
        raise BotError("L'hébergement temporaire n'a pas retourné d'URL")
    return result.download_url

def _safe_unlink(path: Optional[Path]) -> None:
    if path is None:
        return
    try:
        if path.exists():
            path.unlink()
    except OSError:
        LOGGER.debug("Suppression impossible : %s", path)

async def on_error(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    error = context.error
    if isinstance(error, RetryAfter):
        LOGGER.warning("RetryAfter Telegram : %.1fs", error.retry_after)
        return
    if isinstance(error, Forbidden):
        LOGGER.warning("Action interdite par Telegram : %s", error)
        return
    if isinstance(error, BadRequest):
        LOGGER.warning("Requête rejetée par Telegram : %s", error)
        return
    if isinstance(error, NetworkError):
        LOGGER.warning("Erreur réseau Telegram : %s", error)
        return
    LOGGER.exception("Erreur non gérée dans le dispatcher", exc_info=error)

async def _post_init(application: Application) -> None:
    commands = [
        BotCommand("start", "Démarrer le bot"),
        BotCommand("help", "Afficher l'aide"),
        BotCommand("status", "Voir votre quota"),
        BotCommand("arch", "Choisir l'architecture cible"),
    ]
    try:
        await application.bot.set_my_commands(commands)
    except TelegramError as exc:
        LOGGER.warning("Impossible d'enregistrer les commandes : %s", exc)

    me = None
    try:
        me = await application.bot.get_me()
    except TelegramError as exc:
        LOGGER.warning("getMe a échoué : %s", exc)

    if me is not None:
        LOGGER.info("Bot connecté : @%s (id=%s)", me.username, me.id)

async def _post_shutdown(application: Application) -> None:
    dispatcher = application.bot_data.get("dispatcher")
    if isinstance(dispatcher, GitHubDispatcher):
        dispatcher.close()
    LOGGER.info("Bot arrêté proprement.")

def _install_signal_handlers(application: Application) -> None:
    if sys.platform.startswith("win"):
        return
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        return

    def _request_stop() -> None:
        LOGGER.info("Signal d'arrêt reçu, fermeture en cours…")
        try:
            application.stop_running()
        except Exception:  # noqa: BLE001
            LOGGER.debug("stop_running a échoué", exc_info=True)

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _request_stop)
        except (NotImplementedError, RuntimeError):
            continue

def build_application(config: BotConfig) -> Application:
    application = (
        ApplicationBuilder()
        .token(config.telegram_token)
        .post_init(_post_init)
        .post_shutdown(_post_shutdown)
        .build()
    )

    application.bot_data["rate_limiter"] = RateLimiter()
    application.bot_data["deduplicator"] = Deduplicator()
    application.bot_data["semaphore"] = asyncio.Semaphore(RATE_LIMIT_MAX_CONCURRENT)
    application.bot_data["dispatcher"] = GitHubDispatcher(
        pat=config.gh_pat,
        repo=config.gh_repo,
        workflow_file=config.gh_workflow_file,
        ref=config.gh_ref,
    )
    application.bot_data["config"] = config

    application.add_handler(CommandHandler("start", cmd_start))
    application.add_handler(CommandHandler("help", cmd_help))
    application.add_handler(CommandHandler("status", cmd_status))
    application.add_handler(CommandHandler("arch", cmd_arch))

    application.add_handler(
        MessageHandler(filters.Document.ALL, on_document)
    )
    application.add_handler(
        MessageHandler(filters.TEXT & ~filters.COMMAND, on_url)
    )

    application.add_error_handler(on_error)

    return application

def main() -> int:
    try:
        _ensure_directories()
    except BotConfigurationError as exc:
        sys.stderr.write(f"bot: {exc}\n")
        return 2

    _setup_logging(os.environ.get("LOG_LEVEL", "INFO"))

    try:
        config = BotConfig.from_env()
    except BotConfigurationError as exc:
        LOGGER.critical("Configuration invalide : %s", exc)
        sys.stderr.write(f"bot: {exc}\n")
        return 2

    try:
        application = build_application(config)
    except Exception:
        LOGGER.exception("Impossible de construire l'application Telegram")
        return 3

    _install_signal_handlers(application)

    LOGGER.info(
        "Démarrage du bot (dépôt=%s, workflow=%s, ref=%s)",
        config.gh_repo, config.gh_workflow_file, config.gh_ref,
    )

    try:
        application.run_polling(
            allowed_updates=Update.ALL_TYPES,
            drop_pending_updates=True,
            close_loop=True,
            stop_signals=None,
        )
    except KeyboardInterrupt:
        LOGGER.info("Interruption clavier reçue.")
    except TelegramError as exc:
        LOGGER.critical("Erreur Telegram fatale : %s", exc)
        return 4
    except Exception:
        LOGGER.exception("Erreur fatale inattendue")
        return 5

    return 0

if __name__ == "__main__":
    sys.exit(main())
