# VaultgenPro

Modern, lightweight CLI password manager written in Python. Uses a master password and strong encryption to keep your vault secure.

## Highlights
- Master password gate before access
- Password vault: view, add, delete credentials
- Secure notes: create, read, edit, delete
- Built-in password generator with entropy estimate
- Modern CLI with sub-menus (Main -> Vault / Notes / Generator)
- Encrypted local vault file (`vault.json`)

## Security model
- Key derivation: scrypt (auto-tuned on first run, target ~300ms)
- Encryption: AES-GCM with unique nonce per save
- Atomic writes to prevent vault corruption
- Passwords masked by default; reveal per ID with confirmation
- If you lose the master password, the vault cannot be recovered

## Requirements
- Python 3.9+
- pip

## Installation

### Windows (PowerShell)
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### Linux (bash)
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Run

### Windows
```powershell
python vaultgen.py
```

### Linux
```bash
python3 vaultgen.py
```

## Usage
After launch, follow the menus:

### Main
- Vault
- Notes
- Password generator

### Vault
- View passwords (masked by default)
- Reveal password by ID
- Search passwords
- Add a password (URL + notes supported)
- Delete a password

### Notes
- View notes
- Add note
- Edit note
- Delete note

### Generator
- Generate a password
- Choose length, digits, symbols
- Entropy score (faible / moyen / fort)

## Data model
- Entries and notes have stable UUIDs (displayed as short IDs).
- IDs are used for reveal/edit/delete to avoid mistakes.

## Customization
All UI colors and menu styles are configurable at the top of `vaultgen.py`:
- Banner colors: `BANNER_TEXT_STYLE`, `BANNER_BORDER_STYLE`
- Menu colors: `COLOR_MENU_TITLE`, `COLOR_MENU_RULE`, `COLOR_MENU_NUMBER`, `COLOR_MENU_TEXT`, `COLOR_PROMPT`
- Status colors: `COLOR_INFO`, `COLOR_WARNING`, `COLOR_ERROR`, `COLOR_SUCCESS`, `COLOR_PASSWORD`, `COLOR_ID`

Behavior options:
- `SORT_ENTRIES = False` (set `True` to sort entries by name)
- `REVEAL_MODE = "enter"` (or `"timeout"`) and `REVEAL_TIMEOUT_SECONDS`
- `INACTIVITY_LOCK_SECONDS` (set to `0` to disable)
- `KDF_AUTO_TUNE`, `KDF_TARGET_MS`, `KDF_MAX_N`

## Vault file
- Stored in `vault.json` next to the script
- Do not commit this file to git
- Back it up if you want a safe offline copy

## Notes
This project is intended for local use. Review the code and security parameters if you plan to extend it.
