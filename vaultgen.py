from __future__ import annotations

import base64
import json
import math
import os
import secrets
import string
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, IntPrompt, Prompt
from rich.table import Table
from rich.text import Text

APP_NAME = "VaultgenPro"
VAULT_PATH = Path("vault.json")
AAD = b"vaultgenpro|v1"

KDF_PARAMS = {
    "n": 2**15,
    "r": 8,
    "p": 1,
    "length": 32,
}
KDF_AUTO_TUNE = True
KDF_TARGET_MS = 300
KDF_MAX_N = 2**18

SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?/\\|~"
PASSWORD_MASK_CHAR = "*"
PASSWORD_MASK_MIN_LEN = 8
REVEAL_TIMEOUT_SECONDS = 10
ENTRY_ID_DISPLAY_LEN = 8
REVEAL_MODE = "enter"  # "enter" or "timeout"
INACTIVITY_LOCK_SECONDS = 300  # set 0 to disable

BANNER_TEXT_STYLE = "#89B4FA"
BANNER_BORDER_STYLE = "#89B4FA"

COLOR_INFO = "#74C7EC"
COLOR_WARNING = "#F9E2AF"
COLOR_ERROR = "#F38BA8"
COLOR_SUCCESS = "#A6E3A1"

COLOR_PASSWORD = "#CBA6F7"
COLOR_ID = "#89B4FA"

COLOR_MENU_TITLE = "#EDEFF7"
COLOR_MENU_RULE = "#2A2E3E"
COLOR_MENU_NUMBER = "#89B4FA"
COLOR_MENU_TEXT = "#EDEFF7"

COLOR_PROMPT = "#89B4FA"

SORT_ENTRIES = False



MAIN_MENU_OPTIONS = (
    ("1", "Vault"),
    ("2", "Notes"),
    ("3", "Password generator"),
    ("4", "Exit"),
)
MAIN_MENU_DEFAULT = "4"
MAIN_MENU_CHOICES = tuple(key for key, _ in MAIN_MENU_OPTIONS)

VAULT_MENU_OPTIONS = (
    ("1", "View passwords"),
    ("2", "Reveal password"),
    ("3", "Search passwords"),
    ("4", "Add a password"),
    ("5", "Delete a password"),
    ("6", "Back"),
)
VAULT_MENU_DEFAULT = "6"
VAULT_MENU_CHOICES = tuple(key for key, _ in VAULT_MENU_OPTIONS)

GEN_MENU_OPTIONS = (
    ("1", "Generate password"),
    ("2", "Back"),
)
GEN_MENU_DEFAULT = "2"
GEN_MENU_CHOICES = tuple(key for key, _ in GEN_MENU_OPTIONS)

NOTES_MENU_OPTIONS = (
    ("1", "View notes"),
    ("2", "Add note"),
    ("3", "Edit note"),
    ("4", "Delete note"),
    ("5", "Back"),
)
NOTES_MENU_DEFAULT = "5"
NOTES_MENU_CHOICES = tuple(key for key, _ in NOTES_MENU_OPTIONS)

BANNER = r"""
██╗   ██╗ █████╗ ██╗   ██╗██╗  ████████╗ ██████╗ ███████╗███╗   ██╗██████╗ ██████╗  ██████╗ 
██║   ██║██╔══██╗██║   ██║██║  ╚══██╔══╝██╔════╝ ██╔════╝████╗  ██║██╔══██╗██╔══██╗██╔═══██╗
██║   ██║███████║██║   ██║██║     ██║   ██║  ███╗█████╗  ██╔██╗ ██║██████╔╝██████╔╝██║   ██║
╚██╗ ██╔╝██╔══██║██║   ██║██║     ██║   ██║   ██║██╔══╝  ██║╚██╗██║██╔═══╝ ██╔══██╗██║   ██║
 ╚████╔╝ ██║  ██║╚██████╔╝███████╗██║   ╚██████╔╝███████╗██║ ╚████║██║     ██║  ██║╚██████╔╝
  ╚═══╝  ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝    ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═╝     ╚═╝  ╚═╝ ╚═════╝  
                         a simple password vault manager
""".strip("\n")


@dataclass
class VaultData:
    entries: List[Dict[str, str]]
    notes: List[Dict[str, str]]


@dataclass
class VaultSession:
    key: bytes
    salt: bytes
    kdf_params: Dict[str, int]


class VaultError(Exception):
    pass


def _new_id() -> str:
    return uuid.uuid4().hex


def _short_id(value: str) -> str:
    return value[:ENTRY_ID_DISPLAY_LEN]


def _mask_password(value: str) -> str:
    if not value:
        return ""
    return PASSWORD_MASK_CHAR * max(PASSWORD_MASK_MIN_LEN, len(value))


LAST_ACTIVITY = time.monotonic()


def _touch_activity() -> None:
    global LAST_ACTIVITY
    LAST_ACTIVITY = time.monotonic()


class _ActivityScope:
    def __enter__(self) -> None:
        return None

    def __exit__(self, exc_type, exc, tb) -> bool:
        _touch_activity()
        return False


def _activity_scope() -> _ActivityScope:
    return _ActivityScope()


def _lock_if_idle(console: Console, path: Path) -> Optional[tuple[VaultSession, VaultData]]:
    if INACTIVITY_LOCK_SECONDS <= 0:
        return None
    if time.monotonic() - LAST_ACTIVITY < INACTIVITY_LOCK_SECONDS:
        return None
    console.print("Session locked due to inactivity.", style=COLOR_WARNING)
    session, data = _unlock_vault(console, path)
    _touch_activity()
    return session, data


def _b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _b64d(raw: str) -> bytes:
    return base64.b64decode(raw.encode("ascii"))


def _derive_key(password: bytes, salt: bytes, params: Dict[str, int]) -> bytes:
    kdf = Scrypt(
        salt=salt,
        length=params["length"],
        n=params["n"],
        r=params["r"],
        p=params["p"],
    )
    return kdf.derive(password)


def _kdf_params_from_blob(blob: Dict[str, Any]) -> Dict[str, int]:
    kdf = blob.get("kdf", {})
    if not isinstance(kdf, dict):
        raise VaultError("Vault format error")
    if kdf.get("name", "scrypt") != "scrypt":
        raise VaultError("Unsupported KDF")
    params = {
        "n": int(kdf.get("n", KDF_PARAMS["n"])),
        "r": int(kdf.get("r", KDF_PARAMS["r"])),
        "p": int(kdf.get("p", KDF_PARAMS["p"])),
        "length": int(kdf.get("length", KDF_PARAMS["length"])),
    }
    return params


def _salt_from_blob(blob: Dict[str, Any]) -> bytes:
    try:
        return _b64d(blob["salt"])
    except KeyError as exc:
        raise VaultError("Vault format error") from exc


def _encrypt_payload(
    key: bytes, payload: Dict[str, Any], salt: bytes, params: Dict[str, int]
) -> Dict[str, Any]:
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    plaintext = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )
    ciphertext = aesgcm.encrypt(nonce, plaintext, AAD)
    return {
        "version": 1,
        "kdf": {"name": "scrypt", **params},
        "salt": _b64e(salt),
        "nonce": _b64e(nonce),
        "ciphertext": _b64e(ciphertext),
    }


def _decrypt_payload(key: bytes, blob: Dict[str, Any]) -> Dict[str, Any]:
    try:
        nonce = _b64d(blob["nonce"])
        ciphertext = _b64d(blob["ciphertext"])
    except KeyError as exc:
        raise VaultError("Vault format error") from exc

    aesgcm = AESGCM(key)
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, AAD)
    except Exception as exc:
        raise VaultError("Invalid master password or corrupted vault") from exc

    try:
        return json.loads(plaintext.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise VaultError("Vault data is corrupted") from exc


def _atomic_write(path: Path, content: bytes) -> None:
    tmp_path = path.with_name(path.name + ".tmp")
    with open(tmp_path, "wb") as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp_path, path)


def _normalize_entries(entries: List[Any]) -> tuple[List[Dict[str, str]], bool]:
    normalized: List[Dict[str, str]] = []
    changed = False
    for entry in entries:
        if not isinstance(entry, dict):
            raise VaultError("Vault entries are corrupted")
        entry_id = entry.get("id")
        if not isinstance(entry_id, str) or not entry_id.strip():
            entry_id = _new_id()
            changed = True
        normalized_entry: Dict[str, str] = {"id": entry_id}
        for key in ("name", "username", "url", "password", "notes"):
            if key not in entry:
                changed = True
            value = entry.get(key, "")
            if value is None:
                value = ""
                changed = True
            if not isinstance(value, str):
                raise VaultError("Vault entries are corrupted")
            normalized_entry[key] = value
        normalized.append(normalized_entry)
    return normalized, changed


def _normalize_notes(notes: List[Any]) -> tuple[List[Dict[str, str]], bool]:
    normalized: List[Dict[str, str]] = []
    changed = False
    for note in notes:
        if not isinstance(note, dict):
            raise VaultError("Vault notes are corrupted")
        note_id = note.get("id")
        if not isinstance(note_id, str) or not note_id.strip():
            note_id = _new_id()
            changed = True
        normalized_note: Dict[str, str] = {"id": note_id}
        for key in ("title", "body"):
            if key not in note:
                changed = True
            value = note.get(key, "")
            if value is None:
                value = ""
                changed = True
            if not isinstance(value, str):
                raise VaultError("Vault notes are corrupted")
            normalized_note[key] = value
        normalized.append(normalized_note)
    return normalized, changed


def _calibrate_kdf(password: bytes, salt: bytes) -> tuple[Dict[str, int], bytes]:
    if not KDF_AUTO_TUNE:
        params = dict(KDF_PARAMS)
        return params, _derive_key(password, salt, params)
    target = KDF_TARGET_MS / 1000
    n = KDF_PARAMS["n"]
    params = dict(KDF_PARAMS)
    last_key = b""
    while True:
        params["n"] = n
        start = time.perf_counter()
        last_key = _derive_key(password, salt, params)
        elapsed = time.perf_counter() - start
        if elapsed >= target or n >= KDF_MAX_N:
            return dict(params), last_key
        n *= 2


def _load_vault(path: Path, password: str) -> tuple[VaultSession, VaultData, bool]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise VaultError("Vault file not found") from exc
    except json.JSONDecodeError as exc:
        raise VaultError("Vault file is not valid JSON") from exc

    salt = _salt_from_blob(raw)
    params = _kdf_params_from_blob(raw)
    password_bytes = password.encode("utf-8")
    key = _derive_key(password_bytes, salt, params)
    password_bytes = b""
    password = ""
    payload = _decrypt_payload(key, raw)

    entries_raw = payload.get("entries")
    if not isinstance(entries_raw, list):
        raise VaultError("Vault entries missing")
    notes_raw = payload.get("notes", [])
    notes_changed = False
    if notes_raw is None:
        notes_raw = []
        notes_changed = True
    if not isinstance(notes_raw, list):
        raise VaultError("Vault notes missing")

    entries, entries_changed = _normalize_entries(entries_raw)
    notes, normalized_notes_changed = _normalize_notes(notes_raw)
    notes_changed = notes_changed or normalized_notes_changed

    data = VaultData(entries=entries, notes=notes)
    session = VaultSession(key=key, salt=salt, kdf_params=params)
    return session, data, entries_changed or notes_changed


def _save_vault(path: Path, session: VaultSession, data: VaultData) -> None:
    payload = {"entries": data.entries, "notes": data.notes}
    blob = _encrypt_payload(session.key, payload, session.salt, session.kdf_params)
    raw = json.dumps(blob, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    _atomic_write(path, raw)


def _print_banner(console: Console) -> None:
    text = Text(BANNER, style=BANNER_TEXT_STYLE)
    console.print(Panel.fit(text, border_style=BANNER_BORDER_STYLE, title=APP_NAME))


def _print_menu(console: Console, title: str, options: tuple[tuple[str, str], ...]) -> None:
    console.rule(Text(title, style=COLOR_MENU_TITLE), style=COLOR_MENU_RULE)
    for key, label in options:
        line = Text()
        line.append(key, style=COLOR_MENU_NUMBER)
        line.append(" - ", style=COLOR_MENU_TEXT)
        line.append(label, style=COLOR_MENU_TEXT)
        console.print(line)


def _ask_menu_choice(
    console: Console, choices: tuple[str, ...], default: str
) -> Optional[str]:
    while True:
        prompt = Text()
        prompt.append("Choose ", style=COLOR_PROMPT)
        prompt.append("[", style=COLOR_PROMPT)
        for index, key in enumerate(choices):
            if index:
                prompt.append("/", style=COLOR_PROMPT)
            prompt.append(key, style=COLOR_MENU_NUMBER)
        prompt.append("]", style=COLOR_PROMPT)
        prompt.append(f" ({default}): ", style=COLOR_PROMPT)
        console.print(prompt, end="")
        try:
            choice = console.input("").strip()
        except KeyboardInterrupt:
            console.print("\nCanceled.", style=COLOR_WARNING)
            return None
        if not choice:
            choice = default
        if choice in choices:
            _touch_activity()
            return choice
        console.print("Invalid selection.", style=COLOR_ERROR)


def _prompt_new_master(console: Console) -> str:
    console.print("No vault found. Creating a new one.", style=COLOR_WARNING)
    while True:
        first = Prompt.ask("Create master password", password=True)
        second = Prompt.ask("Confirm master password", password=True)
        if first != second:
            console.print("Passwords do not match. Try again.", style=COLOR_ERROR)
            continue
        if len(first) < 8:
            console.print("Password too short (min 8 chars).", style=COLOR_ERROR)
            continue
        return first


def _unlock_vault(console: Console, path: Path) -> tuple[VaultSession, VaultData]:
    if not path.exists():
        master = _prompt_new_master(console)
        salt = os.urandom(16)
        password_bytes = master.encode("utf-8")
        if KDF_AUTO_TUNE:
            console.print(
                "Calibrating encryption (first run only)...", style=COLOR_INFO
            )
        params, key = _calibrate_kdf(password_bytes, salt)
        password_bytes = b""
        master = ""
        session = VaultSession(key=key, salt=salt, kdf_params=params)
        data = VaultData(entries=[], notes=[])
        _save_vault(path, session, data)
        _touch_activity()
        return session, data

    while True:
        master = Prompt.ask("Master password", password=True)
        try:
            session, data, needs_save = _load_vault(path, master)
            master = ""
            if needs_save:
                _save_vault(path, session, data)
            _touch_activity()
            return session, data
        except VaultError as exc:
            console.print(str(exc), style=COLOR_ERROR)
            if not Confirm.ask("Try again?", default=True):
                raise SystemExit(1)


def _render_entries_table(
    console: Console,
    entries: List[Dict[str, str]],
    title: str = "Stored passwords",
    show_passwords: bool = False,
) -> None:
    table = Table(title=title, box=box.SIMPLE_HEAVY)
    table.add_column("ID", style=COLOR_ID, width=ENTRY_ID_DISPLAY_LEN, justify="right")
    table.add_column("Name", style="bold")
    table.add_column("Username")
    table.add_column("URL")
    table.add_column("Notes")
    table.add_column("Password", style=COLOR_PASSWORD)

    for entry in entries:
        password = entry.get("password", "")
        display_password = password if show_passwords else _mask_password(password)
        table.add_row(
            _short_id(entry.get("id", "")),
            entry.get("name", ""),
            entry.get("username", ""),
            entry.get("url", ""),
            entry.get("notes", ""),
            display_password,
        )

    console.print(table)


def _entries_for_display(data: VaultData) -> List[Dict[str, str]]:
    entries = data.entries
    if SORT_ENTRIES:
        return sorted(entries, key=lambda e: e.get("name", ""))
    return entries


def _view_entries(console: Console, data: VaultData) -> None:
    with _activity_scope():
        if not data.entries:
            console.print("No passwords stored yet.", style=COLOR_WARNING)
            return

        _render_entries_table(console, _entries_for_display(data))


def _find_by_id(
    items: List[Dict[str, str]], target: str
) -> Optional[tuple[int, Dict[str, str]]]:
    target = target.strip().lower()
    if not target:
        return None
    matches = [
        (idx, item)
        for idx, item in enumerate(items)
        if item.get("id", "").lower().startswith(target)
    ]
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        raise VaultError(
            f"Ambiguous ID, please type more characters (use {ENTRY_ID_DISPLAY_LEN}+)."
        )
    return None


def _reveal_password(console: Console, data: VaultData) -> None:
    with _activity_scope():
        if not data.entries:
            console.print("No passwords stored yet.", style=COLOR_WARNING)
            return

        _render_entries_table(
            console, _entries_for_display(data), title="Select password to reveal"
        )
        try:
            target = Prompt.ask("Reveal which ID? (blank to cancel)", default="").strip()
        except KeyboardInterrupt:
            console.print("\nCanceled.", style=COLOR_WARNING)
            return
        if not target:
            console.print("Reveal canceled.", style=COLOR_WARNING)
            return
        try:
            match = _find_by_id(data.entries, target)
        except VaultError as exc:
            console.print(str(exc), style=COLOR_ERROR)
            return
        if match is None:
            console.print("ID not found.", style=COLOR_ERROR)
            return
        _, entry = match
        if not Confirm.ask(
            f"Reveal password for '{entry.get('name', '')}'?", default=False
        ):
            console.print("Reveal canceled.", style=COLOR_WARNING)
            return

        console.print(
            f"Password: {entry.get('password', '')}",
            style=COLOR_PASSWORD,
        )
        if REVEAL_MODE == "timeout":
            console.print(
                f"Hiding in {REVEAL_TIMEOUT_SECONDS} seconds...",
                style=COLOR_WARNING,
            )
            time.sleep(REVEAL_TIMEOUT_SECONDS)
        else:
            try:
                console.input("Press Enter to hide ")
            except KeyboardInterrupt:
                console.print("\nCanceled.", style=COLOR_WARNING)
                return


def _search_entries(console: Console, data: VaultData) -> None:
    with _activity_scope():
        if not data.entries:
            console.print("No passwords stored yet.", style=COLOR_WARNING)
            return
        try:
            query = Prompt.ask("Search term", default="").strip()
        except KeyboardInterrupt:
            console.print("\nCanceled.", style=COLOR_WARNING)
            return
        if not query:
            console.print("Search canceled.", style=COLOR_WARNING)
            return
        lowered = query.lower()
        matches = [
            entry
            for entry in data.entries
            if lowered in entry.get("name", "").lower()
            or lowered in entry.get("username", "").lower()
            or lowered in entry.get("url", "").lower()
        ]
        if SORT_ENTRIES:
            matches = sorted(matches, key=lambda e: e.get("name", ""))
        if not matches:
            console.print("No matches found.", style=COLOR_WARNING)
            return
        _render_entries_table(console, matches, title=f"Matches for '{query}'")


def _add_entry(console: Console, data: VaultData) -> None:
    with _activity_scope():
        try:
            name = Prompt.ask("Name / label").strip()
            if not name:
                console.print("Name is required.", style=COLOR_ERROR)
                return

            username = Prompt.ask("Username (optional)", default="")
            url = Prompt.ask("Site URL (optional)", default="")
            password = Prompt.ask("Password", password=True)
            notes = Prompt.ask("Notes (optional)", default="")
        except KeyboardInterrupt:
            console.print("\nCanceled.", style=COLOR_WARNING)
            return

        if not password:
            console.print("Password cannot be empty.", style=COLOR_ERROR)
            return

        data.entries.append(
            {
                "id": _new_id(),
                "name": name,
                "username": username,
                "url": url,
                "password": password,
                "notes": notes,
            }
        )
        console.print("Entry added.", style=COLOR_SUCCESS)


def _generate_password(console: Console) -> None:
    with _activity_scope():
        rng = secrets.SystemRandom()
        try:
            while True:
                length = IntPrompt.ask("Password length", default=16)
                if length < 4 or length > 128:
                    console.print("Length must be between 4 and 128.", style=COLOR_ERROR)
                    continue

                include_digits = Confirm.ask("Include digits?", default=True)
                include_symbols = Confirm.ask("Include symbols?", default=True)

                charsets = [string.ascii_lowercase]
                if include_digits:
                    charsets.append(string.digits)
                if include_symbols:
                    charsets.append(SYMBOLS)

                if length < len(charsets):
                    console.print(
                        f"Length must be at least {len(charsets)} for selected options.",
                        style=COLOR_ERROR,
                    )
                    continue

                alphabet = "".join(charsets)
                password_chars = [rng.choice(cs) for cs in charsets]
                password_chars.extend(
                    rng.choice(alphabet) for _ in range(length - len(charsets))
                )
                rng.shuffle(password_chars)
                password = "".join(password_chars)

                alphabet_size = len(set(alphabet))
                entropy_bits = length * math.log2(alphabet_size)
                if entropy_bits < 40:
                    strength = "faible"
                elif entropy_bits < 60:
                    strength = "moyen"
                else:
                    strength = "fort"

                console.print(f"Generated password: [bold]{password}[/bold]")
                console.print(
                    f"Entropy: {entropy_bits:.1f} bits ({strength})", style=COLOR_INFO
                )
                return
        except KeyboardInterrupt:
            console.print("\nCanceled.", style=COLOR_WARNING)


def _view_notes(console: Console, data: VaultData) -> None:
    with _activity_scope():
        if not data.notes:
            console.print("No notes stored yet.", style=COLOR_WARNING)
            return

        table = Table(title="Secure notes", box=box.SIMPLE_HEAVY)
        table.add_column("ID", style=COLOR_ID, width=ENTRY_ID_DISPLAY_LEN, justify="right")
        table.add_column("Title", style="bold")
        table.add_column("Note")

        for note in data.notes:
            table.add_row(
                _short_id(note.get("id", "")),
                note.get("title", ""),
                note.get("body", ""),
            )

        console.print(table)


def _add_note(console: Console, data: VaultData) -> None:
    with _activity_scope():
        try:
            title = Prompt.ask("Title").strip()
            if not title:
                console.print("Title is required.", style=COLOR_ERROR)
                return
            body = Prompt.ask("Note", default="")
        except KeyboardInterrupt:
            console.print("\nCanceled.", style=COLOR_WARNING)
            return

        data.notes.append({"id": _new_id(), "title": title, "body": body})
        console.print("Note added.", style=COLOR_SUCCESS)


def _edit_note(console: Console, data: VaultData) -> None:
    with _activity_scope():
        if not data.notes:
            console.print("No notes stored yet.", style=COLOR_WARNING)
            return

        table = Table(title="Select note to edit", box=box.SIMPLE_HEAVY)
        table.add_column("ID", style=COLOR_ID, width=ENTRY_ID_DISPLAY_LEN, justify="right")
        table.add_column("Title", style="bold")
        for note in data.notes:
            table.add_row(_short_id(note.get("id", "")), note.get("title", ""))

        console.print(table)
        try:
            target = Prompt.ask("Edit which ID? (blank to cancel)", default="").strip()
        except KeyboardInterrupt:
            console.print("\nCanceled.", style=COLOR_WARNING)
            return
        if not target:
            console.print("Edit canceled.", style=COLOR_WARNING)
            return
        try:
            match = _find_by_id(data.notes, target)
        except VaultError as exc:
            console.print(str(exc), style=COLOR_ERROR)
            return
        if match is None:
            console.print("ID not found.", style=COLOR_ERROR)
            return

        _, note = match
        try:
            title = Prompt.ask("Title", default=note.get("title", ""))
            body = Prompt.ask("Note", default=note.get("body", ""))
        except KeyboardInterrupt:
            console.print("\nCanceled.", style=COLOR_WARNING)
            return
        if not title.strip():
            console.print("Title is required.", style=COLOR_ERROR)
            return

        note["title"] = title
        note["body"] = body
        console.print("Note updated.", style=COLOR_SUCCESS)


def _delete_note(console: Console, data: VaultData) -> None:
    with _activity_scope():
        if not data.notes:
            console.print("No notes stored yet.", style=COLOR_WARNING)
            return

        table = Table(title="Select note to delete", box=box.SIMPLE_HEAVY)
        table.add_column("ID", style=COLOR_ID, width=ENTRY_ID_DISPLAY_LEN, justify="right")
        table.add_column("Title", style="bold")
        for note in data.notes:
            table.add_row(_short_id(note.get("id", "")), note.get("title", ""))

        console.print(table)
        try:
            target = Prompt.ask("Delete which ID? (blank to cancel)", default="").strip()
        except KeyboardInterrupt:
            console.print("\nCanceled.", style=COLOR_WARNING)
            return
        if not target:
            console.print("Delete canceled.", style=COLOR_WARNING)
            return
        try:
            match = _find_by_id(data.notes, target)
        except VaultError as exc:
            console.print(str(exc), style=COLOR_ERROR)
            return
        if match is None:
            console.print("ID not found.", style=COLOR_ERROR)
            return

        index, note = match
        try:
            if Confirm.ask(f"Delete '{note.get('title', '')}'?", default=False):
                data.notes.pop(index)
                console.print("Note deleted.", style=COLOR_SUCCESS)
            else:
                console.print("Delete canceled.", style=COLOR_WARNING)
        except KeyboardInterrupt:
            console.print("\nCanceled.", style=COLOR_WARNING)
            return


def _delete_entry(console: Console, data: VaultData) -> None:
    with _activity_scope():
        if not data.entries:
            console.print("Vault is empty.", style=COLOR_WARNING)
            return

        _render_entries_table(
            console, _entries_for_display(data), title="Select entry to delete"
        )
        try:
            target = Prompt.ask("Delete which ID? (blank to cancel)", default="").strip()
        except KeyboardInterrupt:
            console.print("\nCanceled.", style=COLOR_WARNING)
            return
        if not target:
            console.print("Delete canceled.", style=COLOR_WARNING)
            return
        try:
            match = _find_by_id(data.entries, target)
        except VaultError as exc:
            console.print(str(exc), style=COLOR_ERROR)
            return
        if match is None:
            console.print("ID not found.", style=COLOR_ERROR)
            return

        index, entry = match
        try:
            if Confirm.ask(f"Delete '{entry.get('name', '')}'?", default=False):
                data.entries.pop(index)
                console.print("Entry deleted.", style=COLOR_SUCCESS)
            else:
                console.print("Delete canceled.", style=COLOR_WARNING)
        except KeyboardInterrupt:
            console.print("\nCanceled.", style=COLOR_WARNING)
            return


def _vault_menu(console: Console, session: VaultSession, data: VaultData, path: Path) -> None:
    while True:
        console.print()
        relocked = _lock_if_idle(console, path)
        if relocked:
            session, data = relocked
            continue
        _print_menu(console, "Vault", VAULT_MENU_OPTIONS)
        console.print(f"Entries: {len(data.entries)}", style=COLOR_INFO)

        choice = _ask_menu_choice(console, VAULT_MENU_CHOICES, VAULT_MENU_DEFAULT)
        if choice is None or choice == "6":
            return
        if choice == "1":
            _view_entries(console, data)
        elif choice == "2":
            _reveal_password(console, data)
        elif choice == "3":
            _search_entries(console, data)
        elif choice == "4":
            _add_entry(console, data)
            _save_vault(path, session, data)
        elif choice == "5":
            _delete_entry(console, data)
            _save_vault(path, session, data)


def _generator_menu(console: Console) -> None:
    while True:
        console.print()
        _print_menu(console, "Generator", GEN_MENU_OPTIONS)

        choice = _ask_menu_choice(console, GEN_MENU_CHOICES, GEN_MENU_DEFAULT)
        if choice is None or choice == "2":
            return
        if choice == "1":
            _generate_password(console)


def _notes_menu(console: Console, session: VaultSession, data: VaultData, path: Path) -> None:
    while True:
        console.print()
        relocked = _lock_if_idle(console, path)
        if relocked:
            session, data = relocked
            continue
        _print_menu(console, "Notes", NOTES_MENU_OPTIONS)
        console.print(f"Notes: {len(data.notes)}", style=COLOR_INFO)

        choice = _ask_menu_choice(console, NOTES_MENU_CHOICES, NOTES_MENU_DEFAULT)
        if choice is None or choice == "5":
            return
        if choice == "1":
            _view_notes(console, data)
        elif choice == "2":
            _add_note(console, data)
            _save_vault(path, session, data)
        elif choice == "3":
            _edit_note(console, data)
            _save_vault(path, session, data)
        elif choice == "4":
            _delete_note(console, data)
            _save_vault(path, session, data)


def _menu(console: Console, session: VaultSession, data: VaultData, path: Path) -> None:
    while True:
        console.print()
        relocked = _lock_if_idle(console, path)
        if relocked:
            session, data = relocked
            continue
        _print_menu(console, "Main", MAIN_MENU_OPTIONS)

        choice = _ask_menu_choice(console, MAIN_MENU_CHOICES, MAIN_MENU_DEFAULT)
        if choice is None:
            break
        if choice == "1":
            _vault_menu(console, session, data, path)
        elif choice == "2":
            _notes_menu(console, session, data, path)
        elif choice == "3":
            _generator_menu(console)
        elif choice == "4":
            console.print("Bye!", style=COLOR_INFO)
            break


def main() -> None:
    console = Console()
    console.clear()
    _print_banner(console)
    try:
        session, data = _unlock_vault(console, VAULT_PATH)
    except KeyboardInterrupt:
        console.print("\nCanceled.", style=COLOR_WARNING)
        raise SystemExit(1)

    _menu(console, session, data, VAULT_PATH)


if __name__ == "__main__":
    main()
