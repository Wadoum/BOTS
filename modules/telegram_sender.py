from __future__ import annotations

import argparse
import json
import logging
import mimetypes
import os
import re
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError as exc:
    raise SystemExit(
        "Le module 'requests' est requis. Installez-le via pip install requests."
    ) from exc

LOGGER = logging.getLogger("telegram_sender")
LOGGER.addHandler(logging.NullHandler())

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_LOG_DIR = PROJECT_ROOT / "data" / "logs"

TELEGRAM_API_BASE = "https://api.telegram.org"
TELEGRAM_TOKEN_ENV = "TELEGRAM_TOKEN"
TELEGRAM_CHAT_ID_ENV = "TELEGRAM_CHAT_ID"

TELEGRAM_TEXT_LIMIT = 4096
TELEGRAM_CAPTION_LIMIT = 1024
TELEGRAM_BOT_UPLOAD_LIMIT = 50 * 1024 * 1024
TELEGRAM_BOT_PHOTO_LIMIT = 10 * 1024 * 1024

DEFAULT_CONNECT_TIMEOUT = 20
DEFAULT_READ_TIMEOUT = 120
DEFAULT_UPLOAD_TIMEOUT = 600
DEFAULT_RETRY_TOTAL = 3
DEFAULT_RETRY_BACKOFF = 2.0
DEFAULT_RETRY_STATUS = (429, 500, 502, 503, 504)
DEFAULT_RATE_LIMIT_DELAY = 1.0
MAX_RATE_LIMIT_WAIT = 60.0

ALLOWED_PARSE_MODES: Tuple[str, ...] = ("", "Markdown", "MarkdownV2", "HTML")
ALLOWED_CHAT_ACTIONS: Tuple[str, ...] = (
    "typing",
    "upload_photo",
    "record_video",
    "upload_video",
    "record_voice",
    "upload_voice",
    "upload_document",
    "choose_sticker",
    "find_location",
    "record_video_note",
    "upload_video_note",
)

class TelegramSenderError(Exception):
    pass

class TelegramConfigurationError(TelegramSenderError):
    pass

class TelegramAPIError(TelegramSenderError):
    def __init__(
        self,
        message: str,
        status_code: Optional[int] = None,
        error_code: Optional[int] = None,
        description: str = "",
        retry_after: Optional[float] = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.error_code = error_code
        self.description = description
        self.retry_after = retry_after

class TelegramFileError(TelegramSenderError):
    pass

@dataclass
class SendResult:
    success: bool
    method: str
    chat_id: Optional[Union[int, str]] = None
    message_id: Optional[int] = None
    file_id: Optional[str] = None
    duration_seconds: float = 0.0
    attempts: int = 1
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    raw_response: Optional[Dict[str, Any]] = None

def _read_token() -> str:
    token = os.environ.get(TELEGRAM_TOKEN_ENV)
    if not token:
        raise TelegramConfigurationError(
            f"Variable d'environnement {TELEGRAM_TOKEN_ENV} non définie ou vide."
        )
    token = token.strip()
    if not re.match(r"^\d{6,}:[A-Za-z0-9_-]{30,}$", token):
        raise TelegramConfigurationError(
            f"Format du token Telegram invalide (variable {TELEGRAM_TOKEN_ENV})."
        )
    return token

def _read_default_chat_id() -> Optional[str]:
    value = os.environ.get(TELEGRAM_CHAT_ID_ENV)
    if not value:
        return None
    return value.strip() or None

def _validate_chat_id(chat_id: Union[int, str]) -> Union[int, str]:
    if isinstance(chat_id, int):
        if chat_id == 0:
            raise TelegramConfigurationError("chat_id entier nul invalide")
        return chat_id
    if isinstance(chat_id, str):
        cid = chat_id.strip()
        if not cid:
            raise TelegramConfigurationError("chat_id vide")
        if len(cid) > 128:
            raise TelegramConfigurationError("chat_id trop long")
        return cid
    raise TelegramConfigurationError(
        f"Type de chat_id non supporté : {type(chat_id).__name__}"
    )

def _validate_parse_mode(mode: Optional[str]) -> str:
    if mode is None:
        return ""
    if not isinstance(mode, str):
        raise TelegramConfigurationError("parse_mode doit être une chaîne")
    if mode not in ALLOWED_PARSE_MODES:
        raise TelegramConfigurationError(
            f"parse_mode non supporté : {mode!r}. "
            f"Valeurs autorisées : {ALLOWED_PARSE_MODES}"
        )
    return mode

def _validate_file(path: Path, max_size: int, kind: str) -> None:
    if not path.exists():
        raise TelegramFileError(f"Fichier {kind} introuvable : {path}")
    if not path.is_file():
        raise TelegramFileError(f"Chemin non régulier : {path}")
    size = path.stat().st_size
    if size == 0:
        raise TelegramFileError(f"Fichier {kind} vide : {path}")
    if size > max_size:
        raise TelegramFileError(
            f"Fichier {kind} trop volumineux "
            f"({size} octets > {max_size} octets)"
        )

def _split_message(text: str, limit: int = TELEGRAM_TEXT_LIMIT) -> List[str]:
    if not text:
        return [""]
    if len(text) <= limit:
        return [text]

    chunks: List[str] = []
    remaining = text
    while remaining:
        if len(remaining) <= limit:
            chunks.append(remaining)
            break
        cut = remaining.rfind("\n", 0, limit)
        if cut <= 0:
            cut = remaining.rfind(" ", 0, limit)
        if cut <= 0:
            cut = limit
        chunks.append(remaining[:cut])
        remaining = remaining[cut:].lstrip("\n")
    return chunks

def _escape_html(text: str) -> str:
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )

def _escape_markdown_v2(text: str) -> str:
    specials = r"_*[]()~`>#+-=|{}.!"
    return "".join("\\" + c if c in specials else c for c in text)

class TelegramSender:
    def __init__(
        self,
        token: Optional[str] = None,
        default_chat_id: Optional[Union[int, str]] = None,
        connect_timeout: int = DEFAULT_CONNECT_TIMEOUT,
        read_timeout: int = DEFAULT_READ_TIMEOUT,
        upload_timeout: int = DEFAULT_UPLOAD_TIMEOUT,
        retries: int = DEFAULT_RETRY_TOTAL,
        retry_backoff: float = DEFAULT_RETRY_BACKOFF,
        rate_limit_delay: float = DEFAULT_RATE_LIMIT_DELAY,
    ) -> None:
        self._token = token or _read_token()
        if not self._token:
            raise TelegramConfigurationError("Token Telegram manquant")

        if default_chat_id is None:
            default_chat_id = _read_default_chat_id()
        self._default_chat_id = (
            _validate_chat_id(default_chat_id) if default_chat_id else None
        )

        self._connect_timeout = int(connect_timeout)
        self._read_timeout = int(read_timeout)
        self._upload_timeout = int(upload_timeout)
        self._retries = max(1, int(retries))
        self._retry_backoff = float(retry_backoff)
        self._rate_limit_delay = float(rate_limit_delay)
        self._last_send_ts = 0.0

        self._session = self._build_session()

    def _build_session(self) -> requests.Session:
        session = requests.Session()
        retry = Retry(
            total=self._retries,
            backoff_factor=self._retry_backoff,
            status_forcelist=DEFAULT_RETRY_STATUS,
            allowed_methods=frozenset(["GET", "POST"]),
            raise_on_status=False,
            respect_retry_after_header=True,
        )
        adapter = HTTPAdapter(max_retries=retry, pool_connections=4, pool_maxsize=8)
        session.mount("https://", adapter)
        session.mount("http://", adapter)
        session.headers.update({
            "User-Agent": "BOTS-TelegramSender/1.0",
            "Accept": "application/json",
        })
        return session

    def close(self) -> None:
        try:
            self._session.close()
        except Exception:  # noqa: BLE001
            LOGGER.debug("Fermeture de session échouée", exc_info=True)

    def __enter__(self) -> "TelegramSender":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # type: ignore[no-untyped-def]
        self.close()

    def _endpoint(self, method: str) -> str:
        if not method or not method.isidentifier():
            raise TelegramConfigurationError(f"Méthode Telegram invalide : {method!r}")
        return f"{TELEGRAM_API_BASE}/bot{self._token}/{method}"

    def _apply_rate_limit(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_send_ts
        if elapsed < self._rate_limit_delay:
            time.sleep(self._rate_limit_delay - elapsed)

    def _request(
        self,
        method: str,
        *,
        json_payload: Optional[Dict[str, Any]] = None,
        data_payload: Optional[Dict[str, Any]] = None,
        files: Optional[Dict[str, Any]] = None,
        timeout: Optional[Tuple[int, int]] = None,
    ) -> Dict[str, Any]:
        self._apply_rate_limit()

        url = self._endpoint(method)
        if timeout is None:
            timeout = (self._connect_timeout, self._read_timeout)

        try:
            response = self._session.post(
                url,
                json=json_payload,
                data=data_payload,
                files=files,
                timeout=timeout,
            )
        except requests.RequestException as exc:
            raise TelegramAPIError(
                f"Erreur réseau lors de l'appel {method} : {exc}"
            ) from exc

        self._last_send_ts = time.monotonic()

        try:
            payload = response.json()
        except ValueError:
            raise TelegramAPIError(
                f"Réponse non JSON de l'API Telegram pour {method}",
                status_code=response.status_code,
                description=(response.text or "")[:500],
            )

        if not isinstance(payload, dict):
            raise TelegramAPIError(
                f"Réponse Telegram inattendue pour {method}",
                status_code=response.status_code,
                description=str(payload)[:500],
            )

        if not payload.get("ok"):
            error_code = payload.get("error_code")
            description = payload.get("description") or ""
            retry_after = None
            parameters = payload.get("parameters")
            if isinstance(parameters, dict):
                ra = parameters.get("retry_after")
                if isinstance(ra, (int, float)):
                    retry_after = float(ra)

            if retry_after is not None:
                wait = min(retry_after, MAX_RATE_LIMIT_WAIT)
                LOGGER.warning(
                    "Limite de débit Telegram atteinte pour %s, attente %.1fs",
                    method, wait,
                )
                time.sleep(wait)

            raise TelegramAPIError(
                f"L'API Telegram a retourné une erreur pour {method}",
                status_code=response.status_code,
                error_code=error_code if isinstance(error_code, int) else None,
                description=description,
                retry_after=retry_after,
            )

        return payload

    def get_me(self) -> Dict[str, Any]:
        payload = self._request("getMe", json_payload={})
        result = payload.get("result")
        if not isinstance(result, dict):
            raise TelegramAPIError("getMe n'a pas retourné d'utilisateur")
        return result

    def send_message(
        self,
        text: str,
        chat_id: Optional[Union[int, str]] = None,
        parse_mode: Optional[str] = None,
        disable_web_page_preview: bool = True,
        disable_notification: bool = False,
        reply_to_message_id: Optional[int] = None,
        split_long: bool = True,
    ) -> List[SendResult]:
        if not isinstance(text, str):
            raise TelegramConfigurationError("Le texte du message doit être une chaîne")
        if not text.strip():
            raise TelegramConfigurationError("Le texte du message est vide")

        cid = _validate_chat_id(chat_id or self._default_chat_id or "")
        mode = _validate_parse_mode(parse_mode)

        chunks = _split_message(text) if split_long else [text]
        results: List[SendResult] = []

        for index, chunk in enumerate(chunks):
            if not chunk:
                continue
            if len(chunk) > TELEGRAM_TEXT_LIMIT:
                raise TelegramConfigurationError(
                    f"Segment {index + 1} trop long "
                    f"({len(chunk)} > {TELEGRAM_TEXT_LIMIT})"
                )

            payload: Dict[str, Any] = {
                "chat_id": cid,
                "text": chunk,
                "disable_web_page_preview": disable_web_page_preview,
                "disable_notification": disable_notification,
            }
            if mode:
                payload["parse_mode"] = mode
            if reply_to_message_id is not None and index == 0:
                payload["reply_to_message_id"] = int(reply_to_message_id)

            start = time.monotonic()
            try:
                response = self._request("sendMessage", json_payload=payload)
            except TelegramAPIError as exc:
                results.append(SendResult(
                    success=False,
                    method="sendMessage",
                    chat_id=cid,
                    errors=[str(exc)],
                    duration_seconds=round(time.monotonic() - start, 3),
                ))
                break

            duration = time.monotonic() - start
            result = response.get("result") if isinstance(response, dict) else None
            message_id = None
            if isinstance(result, dict):
                mid = result.get("message_id")
                if isinstance(mid, int):
                    message_id = mid

            results.append(SendResult(
                success=True,
                method="sendMessage",
                chat_id=cid,
                message_id=message_id,
                duration_seconds=round(duration, 3),
                raw_response=response,
            ))

        return results

    def send_document(
        self,
        file_path: Path,
        chat_id: Optional[Union[int, str]] = None,
        caption: str = "",
        parse_mode: Optional[str] = None,
        filename: Optional[str] = None,
        disable_notification: bool = False,
        reply_to_message_id: Optional[int] = None,
    ) -> SendResult:
        path = Path(file_path)
        _validate_file(path, TELEGRAM_BOT_UPLOAD_LIMIT, "document")

        cid = _validate_chat_id(chat_id or self._default_chat_id or "")
        mode = _validate_parse_mode(parse_mode)

        if caption and len(caption) > TELEGRAM_CAPTION_LIMIT:
            raise TelegramConfigurationError(
                f"Légende trop longue ({len(caption)} > {TELEGRAM_CAPTION_LIMIT})"
            )

        data: Dict[str, Any] = {
            "chat_id": cid,
            "disable_notification": disable_notification,
        }
        if caption:
            data["caption"] = caption
            if mode:
                data["parse_mode"] = mode
        if reply_to_message_id is not None:
            data["reply_to_message_id"] = int(reply_to_message_id)

        send_filename = filename or path.name
        content_type = (
            mimetypes.guess_type(send_filename)[0] or "application/octet-stream"
        )

        start = time.monotonic()
        try:
            with path.open("rb") as fh:
                files = {"document": (send_filename, fh, content_type)}
                response = self._request(
                    "sendDocument",
                    data_payload=data,
                    files=files,
                    timeout=(self._connect_timeout, self._upload_timeout),
                )
        except TelegramFileError:
            raise
        except TelegramAPIError as exc:
            return SendResult(
                success=False,
                method="sendDocument",
                chat_id=cid,
                errors=[str(exc)],
                duration_seconds=round(time.monotonic() - start, 3),
            )
        except OSError as exc:
            raise TelegramFileError(
                f"Lecture du fichier impossible : {exc}"
            ) from exc

        duration = time.monotonic() - start
        result = response.get("result") if isinstance(response, dict) else None
        message_id: Optional[int] = None
        file_id: Optional[str] = None

        if isinstance(result, dict):
            mid = result.get("message_id")
            if isinstance(mid, int):
                message_id = mid
            document = result.get("document")
            if isinstance(document, dict):
                fid = document.get("file_id")
                if isinstance(fid, str):
                    file_id = fid

        return SendResult(
            success=True,
            method="sendDocument",
            chat_id=cid,
            message_id=message_id,
            file_id=file_id,
            duration_seconds=round(duration, 3),
            raw_response=response,
        )

    def send_photo(
        self,
        file_path: Path,
        chat_id: Optional[Union[int, str]] = None,
        caption: str = "",
        parse_mode: Optional[str] = None,
        disable_notification: bool = False,
        reply_to_message_id: Optional[int] = None,
    ) -> SendResult:
        path = Path(file_path)
        _validate_file(path, TELEGRAM_BOT_PHOTO_LIMIT, "photo")

        cid = _validate_chat_id(chat_id or self._default_chat_id or "")
        mode = _validate_parse_mode(parse_mode)

        if caption and len(caption) > TELEGRAM_CAPTION_LIMIT:
            raise TelegramConfigurationError(
                f"Légende trop longue ({len(caption)} > {TELEGRAM_CAPTION_LIMIT})"
            )

        data: Dict[str, Any] = {
            "chat_id": cid,
            "disable_notification": disable_notification,
        }
        if caption:
            data["caption"] = caption
            if mode:
                data["parse_mode"] = mode
        if reply_to_message_id is not None:
            data["reply_to_message_id"] = int(reply_to_message_id)

        content_type = mimetypes.guess_type(path.name)[0] or "image/jpeg"

        start = time.monotonic()
        try:
            with path.open("rb") as fh:
                files = {"photo": (path.name, fh, content_type)}
                response = self._request(
                    "sendPhoto",
                    data_payload=data,
                    files=files,
                    timeout=(self._connect_timeout, self._upload_timeout),
                )
        except TelegramFileError:
            raise
        except TelegramAPIError as exc:
            return SendResult(
                success=False,
                method="sendPhoto",
                chat_id=cid,
                errors=[str(exc)],
                duration_seconds=round(time.monotonic() - start, 3),
            )
        except OSError as exc:
            raise TelegramFileError(
                f"Lecture du fichier impossible : {exc}"
            ) from exc

        duration = time.monotonic() - start
        result = response.get("result") if isinstance(response, dict) else None
        message_id: Optional[int] = None
        file_id: Optional[str] = None

        if isinstance(result, dict):
            mid = result.get("message_id")
            if isinstance(mid, int):
                message_id = mid
            photo = result.get("photo")
            if isinstance(photo, list) and photo:
                last = photo[-1]
                if isinstance(last, dict):
                    fid = last.get("file_id")
                    if isinstance(fid, str):
                        file_id = fid

        return SendResult(
            success=True,
            method="sendPhoto",
            chat_id=cid,
            message_id=message_id,
            file_id=file_id,
            duration_seconds=round(duration, 3),
            raw_response=response,
        )

    def send_chat_action(
        self,
        action: str,
        chat_id: Optional[Union[int, str]] = None,
    ) -> SendResult:
        if action not in ALLOWED_CHAT_ACTIONS:
            raise TelegramConfigurationError(
                f"Action non supportée : {action!r}. "
                f"Valeurs autorisées : {ALLOWED_CHAT_ACTIONS}"
            )

        cid = _validate_chat_id(chat_id or self._default_chat_id or "")

        start = time.monotonic()
        try:
            response = self._request(
                "sendChatAction",
                json_payload={"chat_id": cid, "action": action},
            )
        except TelegramAPIError as exc:
            return SendResult(
                success=False,
                method="sendChatAction",
                chat_id=cid,
                errors=[str(exc)],
                duration_seconds=round(time.monotonic() - start, 3),
            )

        return SendResult(
            success=True,
            method="sendChatAction",
            chat_id=cid,
            duration_seconds=round(time.monotonic() - start, 3),
            raw_response=response,
        )

    def delete_message(
        self,
        message_id: int,
        chat_id: Optional[Union[int, str]] = None,
    ) -> SendResult:
        if not isinstance(message_id, int) or message_id <= 0:
            raise TelegramConfigurationError(
                f"message_id invalide : {message_id!r}"
            )

        cid = _validate_chat_id(chat_id or self._default_chat_id or "")

        start = time.monotonic()
        try:
            response = self._request(
                "deleteMessage",
                json_payload={"chat_id": cid, "message_id": message_id},
            )
        except TelegramAPIError as exc:
            return SendResult(
                success=False,
                method="deleteMessage",
                chat_id=cid,
                errors=[str(exc)],
                duration_seconds=round(time.monotonic() - start, 3),
            )

        return SendResult(
            success=True,
            method="deleteMessage",
            chat_id=cid,
            message_id=message_id,
            duration_seconds=round(time.monotonic() - start, 3),
            raw_response=response,
        )

def _build_cli_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="telegram_sender",
        description=(
            "Envoie des messages, documents et photos vers Telegram "
            "via l'API Bot officielle."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    me = sub.add_parser("me", help="Affiche les informations du bot")

    msg = sub.add_parser("send-message", help="Envoie un message texte")
    msg.add_argument("text")
    msg.add_argument("--chat-id", default=None)
    msg.add_argument("--parse-mode", default=None, choices=list(ALLOWED_PARSE_MODES))
    msg.add_argument("--no-split", action="store_true")

    doc = sub.add_parser("send-document", help="Envoie un document")
    doc.add_argument("file", type=Path)
    doc.add_argument("--chat-id", default=None)
    doc.add_argument("--caption", default="")
    doc.add_argument("--parse-mode", default=None, choices=list(ALLOWED_PARSE_MODES))
    doc.add_argument("--filename", default=None)

    photo = sub.add_parser("send-photo", help="Envoie une photo")
    photo.add_argument("file", type=Path)
    photo.add_argument("--chat-id", default=None)
    photo.add_argument("--caption", default="")
    photo.add_argument("--parse-mode", default=None, choices=list(ALLOWED_PARSE_MODES))

    act = sub.add_parser("chat-action", help="Envoie une action de chat")
    act.add_argument("action", choices=list(ALLOWED_CHAT_ACTIONS))
    act.add_argument("--chat-id", default=None)

    for p in (me, msg, doc, photo, act):
        p.add_argument(
            "--log-level",
            default="INFO",
            choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        )

    return parser

def _result_to_dict(result: SendResult) -> Dict[str, Any]:
    payload = asdict(result)
    raw = payload.pop("raw_response", None)
    if raw is not None:
        payload["raw_response_ok"] = bool(raw.get("ok"))
    return payload

def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_cli_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

    try:
        sender = TelegramSender()
    except TelegramConfigurationError as exc:
        LOGGER.error("Configuration invalide : %s", exc)
        sys.stderr.write(f"telegram_sender: {exc}\n")
        return 2

    try:
        if args.command == "me":
            info = sender.get_me()
            sys.stdout.write(json.dumps(info, ensure_ascii=False, indent=2))
            sys.stdout.write("\n")
            return 0

        if args.command == "send-message":
            results = sender.send_message(
                text=args.text,
                chat_id=args.chat_id,
                parse_mode=args.parse_mode,
                split_long=not args.no_split,
            )
            sys.stdout.write(json.dumps(
                [_result_to_dict(r) for r in results],
                ensure_ascii=False, indent=2,
            ))
            sys.stdout.write("\n")
            return 0 if all(r.success for r in results) else 1

        if args.command == "send-document":
            result = sender.send_document(
                file_path=args.file,
                chat_id=args.chat_id,
                caption=args.caption,
                parse_mode=args.parse_mode,
                filename=args.filename,
            )
            sys.stdout.write(json.dumps(
                _result_to_dict(result), ensure_ascii=False, indent=2,
            ))
            sys.stdout.write("\n")
            return 0 if result.success else 1

        if args.command == "send-photo":
            result = sender.send_photo(
                file_path=args.file,
                chat_id=args.chat_id,
                caption=args.caption,
                parse_mode=args.parse_mode,
            )
            sys.stdout.write(json.dumps(
                _result_to_dict(result), ensure_ascii=False, indent=2,
            ))
            sys.stdout.write("\n")
            return 0 if result.success else 1

        if args.command == "chat-action":
            result = sender.send_chat_action(
                action=args.action,
                chat_id=args.chat_id,
            )
            sys.stdout.write(json.dumps(
                _result_to_dict(result), ensure_ascii=False, indent=2,
            ))
            sys.stdout.write("\n")
            return 0 if result.success else 1

        parser.error(f"Commande inconnue : {args.command}")
        return 2
    except TelegramConfigurationError as exc:
        LOGGER.error("Configuration invalide : %s", exc)
        sys.stderr.write(f"telegram_sender: {exc}\n")
        return 2
    except TelegramFileError as exc:
        LOGGER.error("Fichier invalide : %s", exc)
        sys.stderr.write(f"telegram_sender: {exc}\n")
        return 3
    except TelegramAPIError as exc:
        LOGGER.error("Erreur API Telegram : %s", exc)
        if exc.description:
            LOGGER.debug("Description : %s", exc.description)
        sys.stderr.write(f"telegram_sender: {exc}\n")
        return 4
    except Exception:
        LOGGER.exception("Erreur inattendue")
        sys.stderr.write("telegram_sender: erreur inattendue\n")
        return 5
    finally:
        sender.close()

if __name__ == "__main__":
    sys.exit(main())
