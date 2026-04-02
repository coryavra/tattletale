#!/usr/bin/env python3
"""
TattleTale - Post-exploitation NTDS dumpfile analyzer
Analyzes secretsdump output, correlates with hashcat potfiles, identifies shared passwords
"""

import argparse
import contextlib
import csv
import io
import json
import re
import shutil
import sys
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from statistics import median


# =============================================================================
# Constants
# =============================================================================

VERSION = "3.3.0"
MAX_DISPLAY = 10  # Maximum items to show in lists before truncating
HIST_HEIGHT = 8  # Rows for histogram display
BAR_MAX_WIDTH = 12  # Maximum width for bar charts

# Compiled regex for stripping ANSI codes
ANSI_ESCAPE = re.compile(r'\033\[[0-9;]*m')
LABEL_WIDTH = 40  # Left column for labels/names


def get_terminal_width() -> int:
    """Get terminal width, defaulting to 80 if unavailable."""
    try:
        return shutil.get_terminal_size(fallback=(80, 24)).columns
    except Exception:
        return 80


# Dynamic width based on terminal size
WIDTH = get_terminal_width()
VALUE_WIDTH = WIDTH - LABEL_WIDTH - 4  # Right column for values (minus padding)

# Well-known null hashes
NULL_LM = "aad3b435b51404eeaad3b435b51404ee"
NULL_NT = "31d6cfe0d16ae931b73c59d7e0c089c0"

# Well-known AD built-in account RIDs (last component of SID, fixed across all domains)
# RID 502 (krbtgt) is handled separately in the Golden Ticket section
WELL_KNOWN_RIDS: dict[int, str] = {
    500: "Built-in Administrator",
    501: "Guest",
    503: "DefaultAccount",
    504: "WDAGUtilityAccount",
}

# High-privilege group names (lowercase) used for BloodHound matching
HIGH_PRIV_GROUPS = {
    "domain admins", "enterprise admins", "schema admins",
    "administrators", "backup operators", "account operators",
    "print operators", "server operators", "dnsadmins",
    "remote management users", "group policy creator owners",
    "exchange windows permissions", "organization management",
}


LOGO = r"""
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠰⠉⠉⢹⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡆⢸⢹⢸⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡇⢸⣈⢸⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⡐⠒⠶⢶⣦⣤⣇⠀⠉⢸⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣶⣶⣤⣤⣀⣈⠉⠙⠒⠲⠭⢭⣟⣓⡾⠿⣿⣿⣷⣶⣦⣤⣤⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⡆⣤⣭⣙⣛⠿⠿⣶⣶⣬⣥⣒⣪⡭⢿⣓⣿⣿⣿⠿⠟⠛⠛⠻⠿⠷⠶⠤⠄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣧⢻⣿⣿⣿⣿⣷⣶⣤⣍⣙⡛⠿⠿⣿⣿⣿⣧⣤⣀⡈⣥⢴⣶⢶⣾⡿⠿⢿⣶⣦⡀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⣼⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣶⣬⣍⣙⠛⣿⣧⣿⣼⢏⣾⣿⢹⣿⢳⣦⡙⣿⣆⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⣧⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧⢹⣿⡉⣡⣾⢸⣿⡌⣿⠘⣿⣧⢹⣿⡄⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢿⣿⣿⣿⣿⣿⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡜⣿⡇⣿⣿⡆⣿⡇⣿⡆⣿⡟⣸⣿⡇⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⠿⠛⢩⡀⠀⠀⠀⠈⠙⠻⣿⣿⣿⣿⣿⣿⣿⣧⢿⣷⢸⣿⣇⢹⣿⢸⣧⡿⣡⣿⡿⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⠀⠂⠁⠀⠀⠀⠈⠀⠀⠀⠀⠀⠀⠀⠈⠛⠿⣿⣿⣿⣿⣿⡼⣿⡾⠿⠿⠸⣿⠿⣫⣴⣿⠟⠁⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠀⠠⠄⢐⣂⠤⠉⠉⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠐⠚⠀⠀⠈⢙⡿⣿⣿⣷⣿⣇⣿⢻⣦⡻⣿⡿⠛⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡟⠲⢦⣄⣉⠉⠐⠂⠩⠤⠀⣀⠀⠈⠀⠀⠀⠀⣀⠆⠀⠀⠀⠀⠀⠀⢀⠀⠈⠁⠀⢙⣿⣿⣿⣿⠾⠟⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡇⢀⣼⣒⣂⠈⠉⠁⠒⠂⠤⠄⣀⡈⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⠀⠀⢑⣋⢭⣿⣿⡟⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠓⡏⢹⣿⣿⣿⣯⣤⣄⡠⢲⠀⠀⠀⠉⠉⠐⠒⠀⠤⢤⣄⣀⠀⠀⣁⣤⣤⣒⣭⠷⣞⣿⣿⢿⡳⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡇⢸⣷⣾⣭⣝⣛⣻⢃⣉⡍⢶⣶⣤⣤⣄⣉⡑⠒⠺⡇⠉⠹⣿⢻⣿⢹⣭⣶⣿⣿⡿⢿⢸⣿⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡇⢸⣿⣛⣛⠿⠿⣿⠸⣿⣿⣸⣭⣙⣛⠿⠿⣿⣿⣷⣷⡀⠀⣿⠾⢡⣿⡿⣟⣫⣵⣾⣿⢸⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣾⠧⣼⣿⣿⣿⣿⣿⠎⠈⠙⠻⢿⠿⢿⣿⣿⣿⣶⣾⣿⣿⠀⢠⡤⣞⢹⣿⣿⣿⡿⠟⣋⣽⢸⣿⣇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢿⠀⠊⢿⣆⣉⠙⠻⡀⡰⠀⢠⣾⣿⣷⣶⣮⣭⣟⣛⣿⣿⠀⠈⡇⣿⢸⣟⣫⣵⣾⣿⣿⡿⢪⢾⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠓⠺⠟⠢⠬⣀⡈⠒⠊⠉⠛⠛⠿⠿⣿⣿⣿⣿⣿⣿⠀⠀⣷⣿⣸⣿⣿⣿⢿⣫⣽⢡⣿⣼⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠐⠒⠤⢄⣀⡀⠀⠄⣉⣙⠛⣻⡶⠞⣿⣮⣝⠻⣿⣾⣿⠿⠃⠘⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠙⠓⠶⢬⡽⠁⠀⠀⢹⡼⣿⣷⠈⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠙⠓⠲⠶⠛⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
"""

TITLE = r"""
 /$$$$$$$$          /$$     /$$     /$$        /$$$$$$$$        /$$
|__  $$__/         | $$    | $$    | $$       |__  $$__/       | $$
   | $$  /$$$$$$  /$$$$$$ /$$$$$$  | $$  /$$$$$$ | $$  /$$$$$$ | $$  /$$$$$$
   | $$ |____  $$|_  $$_/|_  $$_/  | $$ /$$__  $$| $$ |____  $$| $$ /$$__  $$
   | $$  /$$$$$$$  | $$    | $$    | $$| $$$$$$$$| $$  /$$$$$$$| $$| $$$$$$$$
   | $$ /$$__  $$  | $$ /$$| $$ /$$| $$| $$_____/| $$ /$$__  $$| $$| $$_____/
   | $$|  $$$$$$$  |  $$$$/|  $$$$/| $$|  $$$$$$$| $$|  $$$$$$$| $$|  $$$$$$$
   |__/ \_______/   \___/   \___/  |__/ \_______/|__/ \_______/|__/ \_______/
"""


# =============================================================================
# ANSI Colors
# =============================================================================

class C:
    """ANSI color codes"""
    R = "\033[91m"    # Red
    G = "\033[92m"    # Green
    Y = "\033[93m"    # Yellow
    B = "\033[94m"    # Blue
    M = "\033[95m"    # Magenta
    C = "\033[96m"    # Cyan
    W = "\033[97m"    # White
    GR = "\033[90m"   # Gray
    O = "\033[38;5;208m"  # Orange
    X = "\033[0m"     # Reset
    BD = "\033[1m"    # Bold
    DM = "\033[2m"    # Dim


# =============================================================================
# Data Classes
# =============================================================================

@dataclass
class Credential:
    """Represents a credential extracted from NTDS dump"""
    down_level_logon_name: str = ""
    sam_account_name: str = ""
    domain: str = ""
    lm_hash: str = ""
    nt_hash: str = ""
    cleartext: str = ""
    is_machine: bool = False
    is_target: bool = False
    is_cracked: bool = False
    is_null: bool = False
    target_files: list = field(default_factory=list)
    is_history: bool = False       # True if this is a _historyN entry
    history_index: int = -1        # 0, 1, 2, ... for _history0, _history1, ...
    history_base: str = ""         # SAM name of parent account (e.g. "jsmith")
    rid: int = -1                  # Relative Identifier parsed from secretsdump line
    priv_label: str = ""           # Set when RID matches a WELL_KNOWN_RIDS entry
    bh_groups: list = field(default_factory=list)  # High-priv groups from BloodHound

    @property
    def hash(self) -> str:
        """Returns the primary hash (NT preferred over LM)"""
        if self.nt_hash and self.nt_hash != NULL_NT:
            return self.nt_hash
        if self.lm_hash and self.lm_hash != NULL_LM:
            return self.lm_hash
        return ""

    def __lt__(self, other):
        if self.is_target != other.is_target:
            return self.is_target
        return self.down_level_logon_name.lower() < other.down_level_logon_name.lower()

    def __hash__(self):
        return hash((self.down_level_logon_name, self.hash))

    def __eq__(self, other):
        return (self.down_level_logon_name, self.hash) == (other.down_level_logon_name, other.hash)


# =============================================================================
# Parsing Functions
# =============================================================================

def parse_dit_file(filepath: Path) -> list[Credential]:
    """Parse secretsdump format: DOMAIN\\user:id:LM_hash:NT_hash:::"""
    credentials = []
    try:
        with open(filepath, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(":")
                if len(parts) < 4:
                    continue

                username = parts[0]
                lm_hash = parts[2].lower() if len(parts) > 2 else ""
                nt_hash = parts[3].lower() if len(parts) > 3 else ""

                cred = Credential(down_level_logon_name=username, lm_hash=lm_hash, nt_hash=nt_hash)

                # Extract RID and auto-detect well-known built-in accounts
                try:
                    cred.rid = int(parts[1])
                    if cred.rid in WELL_KNOWN_RIDS:
                        cred.priv_label = WELL_KNOWN_RIDS[cred.rid]
                except (ValueError, IndexError):
                    pass

                if "\\" in username:
                    cred.domain, cred.sam_account_name = username.split("\\", 1)
                else:
                    cred.sam_account_name = username

                cred.is_machine = username.endswith("$")
                # Empty password = NT hash is the null hash (LM is often null even with passwords)
                cred.is_null = (nt_hash == NULL_NT)
                # Detect history entries: DOMAIN\user_history0, _history1, etc.
                history_match = re.search(r'_history(\d+)$', cred.sam_account_name, re.IGNORECASE)
                if history_match:
                    cred.is_history = True
                    cred.history_index = int(history_match.group(1))
                    cred.history_base = cred.sam_account_name[:history_match.start()]
                credentials.append(cred)
    except OSError as e:
        error(f"Failed to read DIT file: {e}")
        sys.exit(1)

    return credentials


def parse_pot_file(filepath: Path) -> dict[str, str]:
    """Parse hashcat potfile format: hash:cleartext"""
    hashes = {}
    try:
        with open(filepath, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line or ":" not in line:
                    continue
                hash_val, cleartext = line.split(":", 1)
                hashes[hash_val.lower()] = cleartext
    except OSError as e:
        error(f"Failed to read potfile: {e}")
        sys.exit(1)
    return hashes


def parse_target_file(filepath: Path) -> set[str]:
    """Parse target file - one username per line. Returns lowercase set."""
    targets = set()
    try:
        with open(filepath, encoding="utf-8", errors="replace") as f:
            for line in f:
                username = line.strip()
                if username:
                    targets.add(username.lower())
    except OSError as e:
        error(f"Failed to read target file: {e}")
        sys.exit(1)
    return targets


def parse_bloodhound_zip(filepath: Path) -> dict[str, list[str]]:
    """Parse a BloodHound/SharpHound zip export.

    Reads *_users.json and *_groups.json from the archive.
    Users file supplies ObjectIdentifier → sAMAccountName mapping.
    Groups file supplies group name → [member ObjectIdentifiers].
    Only high-privilege groups (HIGH_PRIV_GROUPS) are retained.

    Returns {sam_account_name_lower: [group_display_name, ...]}
    """
    try:
        zf = zipfile.ZipFile(filepath)
    except (zipfile.BadZipFile, OSError) as e:
        error(f"Failed to open BloodHound zip: {e}")
        sys.exit(1)

    names = zf.namelist()

    def find_file(keyword: str) -> str | None:
        """Find a file in the zip whose name contains keyword (case-insensitive)."""
        for n in names:
            base = n.split("/")[-1].lower()
            if keyword in base and base.endswith(".json"):
                return n
        return None

    users_file = find_file("users")
    groups_file = find_file("groups")

    if not groups_file:
        error("BloodHound zip does not contain a groups JSON file")
        sys.exit(1)

    # ── Build SID → sAMAccountName map from users file ──
    sid_to_sam: dict[str, str] = {}
    if users_file:
        try:
            users_data = json.loads(zf.read(users_file).decode("utf-8", errors="replace"))
        except (json.JSONDecodeError, KeyError):
            users_data = {}

        entries = users_data.get("data", users_data) if isinstance(users_data, dict) else users_data
        if isinstance(entries, list):
            for entry in entries:
                props = entry.get("Properties", {})
                oid = entry.get("ObjectIdentifier", "")
                sam = props.get("samaccountname", "") or props.get("sAMAccountName", "")
                # Fallback: derive from name "USER@DOMAIN"
                if not sam:
                    name = props.get("name", "")
                    if "@" in name:
                        sam = name.split("@")[0]
                if oid and sam:
                    sid_to_sam[oid.upper()] = sam.lower()

    # ── Parse groups and build sam → [group_names] ──
    try:
        groups_data = json.loads(zf.read(groups_file).decode("utf-8", errors="replace"))
    except json.JSONDecodeError as e:
        error(f"Failed to parse BloodHound groups file: {e}")
        sys.exit(1)

    result: dict[str, list[str]] = {}

    entries = groups_data.get("data", groups_data) if isinstance(groups_data, dict) else groups_data
    if not isinstance(entries, list):
        return result

    for group in entries:
        props = group.get("Properties", {})
        raw_name = props.get("name", "")
        # Group name may be "DOMAIN ADMINS@CORP.LOCAL" — take the part before @
        group_name = raw_name.split("@")[0].strip().lower() if "@" in raw_name else raw_name.lower()

        if group_name not in HIGH_PRIV_GROUPS:
            continue

        display_name = group_name.title()
        members = group.get("Members", [])

        for member in members:
            if member.get("ObjectType", "").lower() != "user":
                continue
            member_sid = member.get("ObjectIdentifier", "").upper()
            sam = sid_to_sam.get(member_sid, "")
            if not sam:
                # Last-resort: SID suffix heuristic won't help here, skip
                continue
            result.setdefault(sam, [])
            if display_name not in result[sam]:
                result[sam].append(display_name)

    zf.close()
    return result


# =============================================================================
# Analysis Helpers
# =============================================================================

def detect_incremental(passwords: list[str]) -> bool:
    """Return True if the password list looks like an incrementing rotation."""
    if len(passwords) < 2:
        return False
    bases = set()
    for pwd in passwords:
        base = re.sub(r'[\d!@#$%^&*()_+=\-]+$', '', pwd)
        base = re.sub(r'^[\d!@#$%^&*()_+=\-]+', '', base).lower()
        if base:
            bases.add(base)
    if len(bases) == 1 and bases:
        return True
    # Two or more passwords both contain a year → likely year-based rotation
    if sum(1 for p in passwords if re.search(r'(19|20)\d{2}', p)) >= 2:
        return True
    return False


# =============================================================================
# Output Functions
# =============================================================================

def banner():
    """Print the banner"""
    print(f"{C.M}{LOGO}{C.X}")
    print(f"{C.C}{TITLE}{C.X}")


def divider(char: str = "─"):
    """Print a divider line"""
    print(f"{C.DM}{char * WIDTH}{C.X}")


def header(title: str, stat: str = "", tree: bool = False):
    """Print a section header with optional right-aligned stat"""
    print()
    if stat:
        visible_title = ANSI_ESCAPE.sub('', title)
        visible_stat = ANSI_ESCAPE.sub('', stat)
        padding = WIDTH - len(visible_title) - len(visible_stat)
        print(f"{C.BD}{C.C}{title}{C.X}{' ' * padding}{stat}")
    else:
        print(f"{C.BD}{C.C}{title}{C.X}")
    if tree:
        print(f"{C.DM}──┬{'─' * (WIDTH - 3)}{C.X}")
    else:
        divider()


def status(message: str):
    """Print a status message"""
    print(f"{C.DM}  {message}{C.X}")


def error(message: str):
    """Print an error message"""
    print(f"{C.R}  Error: {message}{C.X}")


def target_label(filename: str) -> str:
    """Return filename without extension as label"""
    return filename.rsplit(".", 1)[0]


# Colors for target labels - chosen for readability on both dark and light backgrounds
LABEL_COLORS = [
    "\033[36m",  # cyan (dark) - good on both
    "\033[35m",  # magenta (dark) - good on both
    "\033[33m",  # yellow (dark) - good on both
    "\033[32m",  # green (dark) - good on both
    "\033[34m",  # blue (dark) - may be dim on dark, but readable
]


def label_color(filename: str) -> str:
    """Return a consistent color based on filename"""
    # Use sum of char codes for deterministic hash (Python's hash() is randomized per process)
    return LABEL_COLORS[sum(ord(c) for c in filename) % len(LABEL_COLORS)]


# =============================================================================
# Main
# =============================================================================

def print_help():
    """Print styled help menu"""
    print(f"{C.M}{LOGO}{C.X}")
    print(f"{C.C}{TITLE}{C.X}")
    print()
    print(f"{C.BD}USAGE{C.X}")
    print(f"    tattletale -d <file> [-p <file>] [-t <files>] [-b <zip>] [options]")
    print()
    print(f"{C.BD}REQUIRED{C.X}")
    print(f"    {C.C}-d, --dit{C.X} <file>           NTDS.DIT dump file from secretsdump")
    print()
    print(f"{C.BD}OPTIONS{C.X}")
    print(f"    {C.C}-p, --pot{C.X} <file>           Hashcat potfile with cracked hashes")
    print(f"    {C.C}-t, --targets{C.X} <files>      Target lists, space-separated (e.g. -t admins.txt svc.txt)")
    print(f"    {C.C}-b, --bloodhound{C.X} <zip>     BloodHound/SharpHound zip export for group membership context")
    print(f"    {C.C}-o, --output{C.X} <dir>         Export reports to directory")
    print(f"    {C.C}-r, --redact{C.X}               Hide passwords completely (************)")
    print(f"    {C.C}-R, --redact-partial{C.X}       Show first two chars only (Pa**********)")
    print(f"    {C.C}-h, --help{C.X}                 Show this help message")
    print(f"    {C.C}-v, --version{C.X}              Show version number")
    print()
    print(f"{C.BD}POLICY{C.X} {C.DM}(check cracked passwords against requirements){C.X}")
    print(f"    {C.C}--policy-length{C.X} <n>        Minimum password length")
    print(f"    {C.C}--policy-complexity{C.X} <n>    Require n-of-4 character classes (1-4)")
    print(f"                               {C.DM}(uppercase, lowercase, digit, symbol){C.X}")
    print()
    print(f"{C.BD}EXAMPLES{C.X}")
    print(f"    {C.DM}# Basic analysis{C.X}")
    print(f"    tattletale -d ntds.dit")
    print()
    print(f"    {C.DM}# With cracked hashes{C.X}")
    print(f"    tattletale -d ntds.dit -p hashcat.potfile")
    print()
    print(f"    {C.DM}# Full analysis with multiple target lists{C.X}")
    print(f"    tattletale -d ntds.dit -p cracked.pot -t domain_admins.txt local_admins.txt")
    print()
    print(f"    {C.DM}# With BloodHound group membership enrichment{C.X}")
    print(f"    tattletale -d ntds.dit -p cracked.pot -b BloodHound_2024.zip")
    print()
    print(f"    {C.DM}# Full analysis — cracked hashes, targets, and BloodHound context{C.X}")
    print(f"    tattletale -d ntds.dit -p cracked.pot -t da.txt svc.txt -b BloodHound.zip")
    print()
    print(f"    {C.DM}# Redacted output for sharing{C.X}")
    print(f"    tattletale -d ntds.dit -p cracked.pot -r")
    print()
    print(f"    {C.DM}# Check against password policy (Windows default){C.X}")
    print(f"    tattletale -d ntds.dit -p cracked.pot --policy-length 8 --policy-complexity 3")
    print()
    print(f"{C.BD}INPUT FORMATS{C.X}")
    print(f"    {C.C}DIT file{C.X}      secretsdump format: DOMAIN\\user:RID:LM:NT:::")
    print(f"    {C.C}Potfile{C.X}       hashcat format: HASH:cleartext")
    print(f"    {C.C}Targets{C.X}       One username per line (SAM account name)")
    print()


def main():
    # Show help if no arguments
    if len(sys.argv) == 1:
        print_help()
        sys.exit(0)

    # Check for help flag manually (before argparse)
    if "-h" in sys.argv or "--help" in sys.argv:
        print_help()
        sys.exit(0)

    # Check for version flag
    if "-v" in sys.argv or "--version" in sys.argv:
        print(f"TattleTale v{VERSION}")
        sys.exit(0)

    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("-d", "--dit", required=True)
    parser.add_argument("-p", "--pot")
    parser.add_argument("-t", "--targets", nargs="+")
    parser.add_argument("-b", "--bloodhound")
    parser.add_argument("-o", "--output")
    parser.add_argument("-r", "--redact", action="store_true")
    parser.add_argument("-R", "--redact-partial", action="store_true")
    parser.add_argument("--policy-length", type=int)
    parser.add_argument("--policy-complexity", type=int, choices=[1, 2, 3, 4])
    parser.add_argument("-h", "--help", action="store_true")

    # Capture stderr to suppress argparse's ugly output
    stderr_capture = io.StringIO()
    try:
        with contextlib.redirect_stderr(stderr_capture):
            args = parser.parse_args()
    except SystemExit:
        print_help()
        sys.exit(1)

    # Redaction function (fixed width to hide password length)
    def redact(password: str, color: bool = True) -> str:
        if not password:
            return password
        gr = C.GR if color else ""
        x = C.X if color else ""
        if args.redact:
            return f"{gr}************{x}"
        if args.redact_partial:
            prefix = password[:2] if len(password) >= 2 else password[0]
            return f"{prefix}{gr}**********{x}"
        return password

    # Banner
    banner()
    print()

    # If --output is set, tee all terminal output to tt-output.txt as well
    _tee_file = None
    if args.output:
        try:
            _out_dir = Path(args.output)
            _out_dir.mkdir(parents=True, exist_ok=True)
            _tee_file = open(_out_dir / "tt-output.txt", "w", encoding="utf-8")

            class _Tee:
                def __init__(self, real, tee):
                    self._real = real
                    self._tee = tee
                def write(self, data):
                    self._real.write(data)
                    # Strip ANSI codes before writing to file
                    self._tee.write(ANSI_ESCAPE.sub('', data))
                def flush(self):
                    self._real.flush()
                    self._tee.flush()
                def fileno(self):
                    return self._real.fileno()

            sys.stdout = _Tee(sys.stdout, _tee_file)
        except OSError:
            pass  # Non-fatal; output continues normally to terminal

    # Parse files
    all_credentials: list[Credential] = []
    pot_hashes: dict[str, str] = {}
    targets: set[str] = set()

    # Parse DIT file
    dit_path = Path(args.dit)
    if not dit_path.exists():
        error(f"DIT file not found: {args.dit}")
        sys.exit(1)
    status(f"Parsing {dit_path.name}...")
    creds = parse_dit_file(dit_path)
    all_credentials.extend(creds)
    print(f"  {C.DM}└─ Found {len(creds)} credentials{C.X}")

    # Parse potfile
    if args.pot:
        pot_path = Path(args.pot)
        if not pot_path.exists():
            error(f"Potfile not found: {args.pot}")
            sys.exit(1)
        status(f"Parsing {pot_path.name}...")
        hashes = parse_pot_file(pot_path)
        pot_hashes.update(hashes)
        print(f"  {C.DM}├─ Found {len(hashes)} cracked hashes{C.X}")

        # Correlate cracked hashes
        cracked_count = 0
        for cred in all_credentials:
            if cred.hash in pot_hashes:
                cred.cleartext = pot_hashes[cred.hash]
                cred.is_cracked = True
                cracked_count += 1
        print(f"  {C.DM}└─ Matched {cracked_count} credentials{C.X}")
    else:
        print(f"  {C.Y}⚠ No potfile provided{C.X} {C.DM}(use -p/--pot to correlate cracked hashes){C.X}")

    # Parse target files
    if args.targets:
        for target_path in args.targets:
            path = Path(target_path)
            if not path.exists():
                error(f"Target file not found: {target_path}")
                sys.exit(1)
            status(f"Parsing {path.name}...")
            file_targets = parse_target_file(path)  # Already lowercase set
            targets.update(file_targets)
            for cred in all_credentials:
                if cred.sam_account_name.lower() in file_targets:
                    cred.is_target = True
                    cred.target_files.append(path.name)
            print(f"  {C.DM}└─ Found {len(file_targets)} targets{C.X}")
    else:
        print(f"  {C.Y}⚠ No target file provided{C.X} {C.DM}(use -t/--targets to track high-value accounts){C.X}")

    # Parse BloodHound zip
    bh_groups: dict[str, list[str]] = {}
    if args.bloodhound:
        bh_path = Path(args.bloodhound)
        if not bh_path.exists():
            error(f"BloodHound zip not found: {args.bloodhound}")
            sys.exit(1)
        status(f"Parsing {bh_path.name}...")
        bh_groups = parse_bloodhound_zip(bh_path)
        print(f"  {C.DM}└─ Found {len(bh_groups)} users with high-priv group memberships{C.X}")

    # Remove duplicates
    all_credentials = list(dict.fromkeys(all_credentials))

    # Apply BloodHound group memberships
    if bh_groups:
        for cred in all_credentials:
            if not cred.is_history and not cred.is_machine:
                groups = bh_groups.get(cred.sam_account_name.lower(), [])
                if groups:
                    cred.bh_groups = groups

    # ==========================================================================
    # Statistics
    # ==========================================================================
    users = [c for c in all_credentials if not c.is_machine and not c.is_history]
    machines = [c for c in all_credentials if c.is_machine and not c.is_history]
    null_users = [c for c in users if c.is_null]
    valid_users = [c for c in users if not c.is_null]
    cracked_users = [c for c in valid_users if c.is_cracked]
    lm_creds = [c for c in all_credentials if c.lm_hash and c.lm_hash != NULL_LM]
    nt_creds = [c for c in all_credentials if c.nt_hash and c.nt_hash != NULL_NT]

    # Header with crack rate
    if valid_users:
        pct = len(cracked_users) / len(valid_users)
        header("Statistics", f"{C.G}{len(cracked_users)}{C.X}/{len(valid_users)} cracked ({pct*100:.0f}%)")
    else:
        header("Statistics")

    # Compact stats
    acct_parts = [f"{len(users)} users", f"{len(machines)} machines"]
    if null_users:
        acct_parts.append(f"{len(null_users)} empty")
    print(f"  {C.DM}Accounts{C.X}   {', '.join(acct_parts)}")

    hash_parts = [f"{len(nt_creds)} NT"]
    if lm_creds:
        hash_parts.append(f"{C.Y}{len(lm_creds)} LM (legacy){C.X}")
    else:
        hash_parts.append("0 LM")
    print(f"  {C.DM}Hashes{C.X}     {', '.join(hash_parts)}")

    if valid_users:
        unique_hashes = len(set(c.hash for c in valid_users if c.hash))
        unique_cracked = len(set(c.cleartext for c in cracked_users if c.cleartext))
        print(f"  {C.DM}Unique{C.X}     {unique_cracked}/{unique_hashes} unique password hashes cracked")

    # Security warnings with tree format
    empty_password_users = [c for c in users if c.nt_hash == NULL_NT]
    lm_users = [c for c in users if c.lm_hash and c.lm_hash != NULL_LM]

    if empty_password_users:
        print()
        print(f"  {C.R}⚠ {len(empty_password_users)} accounts have NO PASSWORD{C.X} {C.DM}(often disabled, but verify){C.X}")
        sorted_empty = sorted(empty_password_users, key=lambda c: (not c.is_target, c.sam_account_name))
        display_count = min(len(sorted_empty), MAX_DISPLAY)
        remaining = len(sorted_empty) - display_count
        for i, cred in enumerate(sorted_empty[:display_count]):
            is_last = (i == display_count - 1) and remaining == 0
            prefix = "└─" if is_last else "├─"
            if cred.is_target:
                labels = ", ".join(f"{label_color(f)}{target_label(f)}{C.X}" for f in cred.target_files)
                print(f"  {C.DM}{prefix}{C.X} {C.W}{cred.sam_account_name}{C.X}  {labels}")
            else:
                print(f"  {C.DM}{prefix} {cred.sam_account_name}{C.X}")
        if remaining > 0:
            hint = f"  {C.DM}(full list in tt-empty-passwords.txt){C.X}" if args.output else ""
            print(f"  {C.DM}└─ ... and {remaining} more{C.X}{hint}")

    if lm_users:
        print()
        print(f"  {C.O}⚠ {len(lm_users)} accounts have LM hashes{C.X} {C.DM}(weak legacy format){C.X}")
        sorted_lm = sorted(lm_users, key=lambda c: (not c.is_target, c.sam_account_name))
        display_count = min(len(sorted_lm), MAX_DISPLAY)
        remaining = len(sorted_lm) - display_count
        for i, cred in enumerate(sorted_lm[:display_count]):
            is_last = (i == display_count - 1) and remaining == 0
            prefix = "└─" if is_last else "├─"
            if cred.is_target:
                labels = ", ".join(f"{label_color(f)}{target_label(f)}{C.X}" for f in cred.target_files)
                print(f"  {C.DM}{prefix}{C.X} {C.W}{cred.sam_account_name}{C.X}  {labels}")
            else:
                print(f"  {C.DM}{prefix} {cred.sam_account_name}{C.X}")
        if remaining > 0:
            hint = f"  {C.DM}(full list in tt-lm-hashes.txt){C.X}" if args.output else ""
            print(f"  {C.DM}└─ ... and {remaining} more{C.X}{hint}")

    # ==========================================================================
    # krbtgt Detection — Golden Ticket Risk
    # ==========================================================================
    krbtgt_creds = [c for c in all_credentials
                    if c.sam_account_name.lower() == "krbtgt" and not c.is_history]
    if krbtgt_creds:
        any_cracked = any(c.is_cracked for c in krbtgt_creds)
        stat_str = f"{C.R}CRITICAL{C.X}" if any_cracked else f"{C.Y}not cracked{C.X}"
        header("krbtgt — Kerberos Trust Account", stat_str)
        sorted_krbtgt = sorted(krbtgt_creds, key=lambda c: c.down_level_logon_name)
        for i, cred in enumerate(sorted_krbtgt):
            is_last = (i == len(sorted_krbtgt) - 1)
            prefix = "└─" if is_last else "├─"
            left_len = 5 + len(cred.down_level_logon_name)
            if cred.is_cracked:
                pwd_display = redact(cred.cleartext)
                right_len = 12 if (args.redact or args.redact_partial) else len(cred.cleartext)
                dots = " " + "·" * max(WIDTH - left_len - right_len - 2, 1) + " "
                print(f"  {C.DM}{prefix}{C.X} {C.W}{cred.down_level_logon_name}{C.X}{C.DM}{dots}{C.X}{pwd_display}")
            else:
                tag = "(not cracked)"
                dots = " " + "·" * max(WIDTH - left_len - len(tag) - 2, 1) + " "
                print(f"  {C.DM}{prefix}{C.X} {C.W}{cred.down_level_logon_name}{C.X}{C.DM}{dots}{C.O}{tag}{C.X}")
        if any_cracked:
            print()
            print(f"  {C.R}⚠ Cracked krbtgt enables forged Kerberos tickets (Golden Ticket){C.X}")

    # ==========================================================================
    # High Value Targets
    # ==========================================================================
    # Shared Hashes (calculate first for column widths)
    # ==========================================================================
    hash_to_creds: dict[str, list[Credential]] = {}
    for cred in all_credentials:
        if cred.hash and not cred.is_null and not cred.is_history:
            if cred.hash not in hash_to_creds:
                hash_to_creds[cred.hash] = []
            hash_to_creds[cred.hash].append(cred)

    shared_hashes = {h: creds for h, creds in hash_to_creds.items() if len(creds) > 1}

    def is_notable(cred: Credential) -> bool:
        """True if account is a manual target or identified as privileged via BloodHound."""
        return cred.is_target or bool(cred.bh_groups)

    def cred_right_label(cred: Credential) -> str:
        """Plain-text label shown on the right side of a credential row."""
        if cred.is_target:
            return ", ".join(target_label(f) for f in cred.target_files)
        if cred.bh_groups:
            return ", ".join(cred.bh_groups)
        return ""

    def cred_right_label_colored(cred: Credential) -> str:
        """ANSI-colored label shown on the right side of a credential row."""
        if cred.is_target:
            return ", ".join(f"{label_color(f)}{target_label(f)}{C.X}" for f in cred.target_files)
        if cred.bh_groups:
            return f"{C.O}{', '.join(cred.bh_groups)}{C.X}"
        return ""

    # Filter to only shared hashes involving notable accounts (targets or BH-privileged)
    target_shared_hashes = {h: creds for h, creds in shared_hashes.items()
                           if any(is_notable(c) for c in creds)}

    # Manual target accounts
    target_creds = sorted([c for c in all_credentials if c.is_target])
    # BloodHound-privileged accounts not already in a target file
    bh_priv_creds = sorted([c for c in all_credentials
                             if c.bh_groups and not c.is_target
                             and not c.is_history and not c.is_machine])

    all_notable_creds = list({id(c): c for c in target_creds + bh_priv_creds}.values())
    all_shared_creds = [c for creds in target_shared_hashes.values() for c in creds] if target_shared_hashes else []
    all_display_creds = list({id(c): c for c in all_notable_creds + all_shared_creds}.values())

    if all_display_creds:
        max_name = max(len(c.down_level_logon_name) for c in all_display_creds)
    else:
        max_name = 0

    # ==========================================================================
    # High Value Targets (grouped by target file, then BloodHound groups)
    # ==========================================================================
    if target_creds or bh_priv_creds:
        # Group credentials by target file
        file_to_creds: dict[str, list[Credential]] = {}
        for cred in target_creds:
            for f in cred.target_files:
                if f not in file_to_creds:
                    file_to_creds[f] = []
                file_to_creds[f].append(cred)

        # Group BH-only accounts by group name
        bh_group_to_creds: dict[str, list[Credential]] = {}
        for cred in bh_priv_creds:
            for grp in cred.bh_groups:
                bh_group_to_creds.setdefault(grp, []).append(cred)

        total_notable = len(target_creds) + len(bh_priv_creds)
        unique_cracked = len([c for c in target_creds if c.is_cracked]) + len([c for c in bh_priv_creds if c.is_cracked])
        header("High Value Targets", f"{C.G}{unique_cracked}{C.X}/{total_notable} cracked")

        sorted_files = sorted(file_to_creds.items(), key=lambda x: x[0])
        for file_idx, (filename, creds) in enumerate(sorted_files):
            is_last_file = (file_idx == len(sorted_files) - 1)
            file_cracked = len([c for c in creds if c.is_cracked])
            label = target_label(filename)
            count_str = f"{file_cracked} / {len(creds)}"

            # File header: "  ├─ label ····· count"
            file_prefix = "└─" if is_last_file else "├─"
            # "  ├─ " = 5 chars prefix
            left_len = 5 + len(label)
            right_len = len(count_str)
            dots_len = WIDTH - left_len - right_len
            dots = " " + "·" * max(dots_len - 2, 1) + " "
            color = label_color(filename)
            count_display = f"{C.DM}{count_str}{C.X}"
            print(f"  {C.DM}{file_prefix}{C.X} {color}{label}{C.X}{C.DM}{dots}{C.X}{count_display}")

            # List credentials under this file
            sorted_creds = sorted(creds, key=lambda c: (not c.is_cracked, c.down_level_logon_name))
            tree_prefix = "   " if is_last_file else "│  "
            for cred_idx, cred in enumerate(sorted_creds):
                is_last_cred = (cred_idx == len(sorted_creds) - 1)
                cred_prefix = "└─" if is_last_cred else "├─"

                # "  │  ├─ " = 8 chars prefix
                left_len = 8 + len(cred.down_level_logon_name)

                if cred.is_cracked:
                    pwd_display = redact(cred.cleartext)
                    # Calculate visible length accounting for redaction
                    if args.redact:
                        right_len = 12  # "************"
                    elif args.redact_partial:
                        right_len = 12  # "XX**********"
                    else:
                        right_len = len(cred.cleartext)
                    dots_len = WIDTH - left_len - right_len
                    dots = " " + "·" * max(dots_len - 2, 1) + " "
                    print(f"  {C.DM}{tree_prefix}{cred_prefix}{C.X} {C.W}{cred.down_level_logon_name}{C.X}{C.DM}{dots}{C.X}{pwd_display}")
                else:
                    not_cracked = "(not cracked)"
                    right_len = len(not_cracked)
                    dots_len = WIDTH - left_len - right_len
                    dots = " " + "·" * max(dots_len - 2, 1) + " "
                    print(f"  {C.DM}{tree_prefix}{cred_prefix}{C.X} {C.W}{cred.down_level_logon_name}{C.X}{C.DM}{dots}{C.X}{C.O}{not_cracked}{C.X}")

            # Empty line between file groups (except after last)
            if not is_last_file:
                print(f"  {C.DM}│{C.X}")

        # BloodHound-privileged accounts grouped by group name
        if bh_group_to_creds:
            if file_to_creds:
                print()  # separator between target-file block and BH block
            TIER1_GROUPS = {"enterprise admins", "domain admins", "administrators"}
            sorted_bh_groups = sorted(
                bh_group_to_creds.items(),
                key=lambda x: (0 if x[0].lower() in TIER1_GROUPS else 1, x[0].lower())
            )
            for grp_idx, (grp, grp_creds) in enumerate(sorted_bh_groups):
                is_last_grp = (grp_idx == len(sorted_bh_groups) - 1)
                grp_cracked = len([c for c in grp_creds if c.is_cracked])
                count_str = f"{grp_cracked} / {len(grp_creds)}"
                grp_prefix = "└─" if is_last_grp else "├─"
                left_len = 5 + len(grp)
                right_len = len(count_str)
                dots = " " + "·" * max(WIDTH - left_len - right_len - 2, 1) + " "
                print(f"  {C.DM}{grp_prefix}{C.X} {C.O}{grp}{C.X}{C.DM}{dots}{C.X}{C.DM}{count_str}{C.X}")

                tree_prefix = "   " if is_last_grp else "│  "
                sorted_creds = sorted(grp_creds, key=lambda c: (not c.is_cracked, c.down_level_logon_name))
                for cred_idx, cred in enumerate(sorted_creds):
                    is_last_cred = (cred_idx == len(sorted_creds) - 1)
                    cred_prefix = "└─" if is_last_cred else "├─"
                    left_len = 8 + len(cred.down_level_logon_name)
                    if cred.is_cracked:
                        pwd_display = redact(cred.cleartext)
                        right_len = 12 if (args.redact or args.redact_partial) else len(cred.cleartext)
                        dots = " " + "·" * max(WIDTH - left_len - right_len - 2, 1) + " "
                        print(f"  {C.DM}{tree_prefix}{cred_prefix}{C.X} {C.W}{cred.down_level_logon_name}{C.X}{C.DM}{dots}{C.X}{pwd_display}")
                    else:
                        tag = "(not cracked)"
                        dots = " " + "·" * max(WIDTH - left_len - len(tag) - 2, 1) + " "
                        print(f"  {C.DM}{tree_prefix}{cred_prefix}{C.X} {C.W}{cred.down_level_logon_name}{C.X}{C.DM}{dots}{C.X}{C.O}{tag}{C.X}")

                if not is_last_grp:
                    print(f"  {C.DM}│{C.X}")

    # ==========================================================================
    # Shared Target Credentials
    # ==========================================================================
    has_notable = bool(targets or bh_groups)
    if has_notable and not target_shared_hashes:
        header("Shared Target Credentials", "none")
        print(f"  {C.DM}No notable accounts share a password hash with any other account{C.X}")
        print()

    if has_notable and target_shared_hashes:
        total_shared_accounts = sum(len(creds) for creds in target_shared_hashes.values())
        header("Shared Target Credentials", f"{C.G}{len(target_shared_hashes)}{C.X} groups, {total_shared_accounts} accounts")

        # Calculate max widths from actual data
        all_shared_creds = [c for creds in target_shared_hashes.values() for c in creds]
        max_name_len = max(len(c.down_level_logon_name) for c in all_shared_creds) if all_shared_creds else 30

        SHARED_TIER1 = {"enterprise admins", "domain admins", "administrators"}

        def shared_group_priority(item):
            _, creds = item
            # Tier 0: group contains a tier-1 BH-privileged account
            has_tier1 = any(
                any(g.lower() in SHARED_TIER1 for g in c.bh_groups)
                for c in creds if is_notable(c)
            )
            # Tier 1: group contains any other notable account
            has_notable = any(is_notable(c) for c in creds)
            return (0 if has_tier1 else 1 if has_notable else 2, -len(creds))

        sorted_groups = sorted(target_shared_hashes.items(), key=shared_group_priority)
        for group_idx, (hash_val, creds) in enumerate(sorted_groups):
            is_last_group = (group_idx == len(sorted_groups) - 1)
            cleartext = ""
            for c in creds:
                if c.is_cracked:
                    cleartext = c.cleartext
                    break

            if cleartext:
                pwd_display = redact(cleartext)
                # Calculate visible length accounting for redaction
                if args.redact:
                    pwd_visible_len = 12  # "************"
                elif args.redact_partial:
                    pwd_visible_len = 12  # "XX**********"
                else:
                    pwd_visible_len = len(cleartext)
            else:
                hash_display = redact(hash_val, color=False) if (args.redact or args.redact_partial) else hash_val
                pwd_display = f"{C.O}{hash_display} (not cracked){C.X}"
                # Visible: hash_display + " (not cracked)"
                if args.redact:
                    pwd_visible_len = 12 + len(" (not cracked)")
                elif args.redact_partial:
                    pwd_visible_len = 12 + len(" (not cracked)")
                else:
                    pwd_visible_len = len(hash_val) + len(" (not cracked)")

            # Group header with password and count right-aligned
            group_prefix = "└─" if is_last_group else "├─"
            count_str = f"{len(creds)} accounts"
            # "  ├─ " = 5 chars prefix, dots need " · " minimum (3 chars)
            left_len = 5 + pwd_visible_len
            right_len = len(count_str)
            dots_len = WIDTH - left_len - right_len
            dots = " " + "·" * max(dots_len - 2, 1) + " "
            count_display = f"{C.DM}{count_str}{C.X}"
            print(f"  {C.DM}{group_prefix}{C.X} {pwd_display}{C.DM}{dots}{C.X}{count_display}")

            # List all accounts (notable first, then others)
            notable_in_group = sorted([c for c in creds if is_notable(c)])
            other_creds = sorted([c for c in creds if not is_notable(c)])
            all_sorted = notable_in_group + other_creds

            tree_prefix = "   " if is_last_group else "│  "
            for i, cred in enumerate(all_sorted):
                is_last = (i == len(all_sorted) - 1)
                cred_prefix = "└─" if is_last else "├─"

                left_len = 8 + len(cred.down_level_logon_name)

                if is_notable(cred):
                    plain_lbl = cred_right_label(cred)
                    colored_lbl = cred_right_label_colored(cred)
                    # Truncate target-file labels if too long (BH group names are short)
                    if cred.is_target:
                        MIN_DOTS = 10
                        max_label_len = WIDTH - left_len - MIN_DOTS
                        label_list = [target_label(f) for f in cred.target_files]
                        file_list = list(cred.target_files)
                        included_idx = []
                        current_len = 0
                        for label_idx, lbl in enumerate(label_list):
                            sep_len = 2 if label_idx > 0 else 0
                            if current_len + sep_len + len(lbl) <= max_label_len:
                                included_idx.append(label_idx)
                                current_len += sep_len + len(lbl)
                            else:
                                break
                        remaining = len(label_list) - len(included_idx)
                        if remaining > 0:
                            suffix_len = 2 + len(f"+{remaining}")
                            while included_idx and current_len + suffix_len > max_label_len:
                                removed_idx = included_idx.pop()
                                current_len -= len(label_list[removed_idx]) + (2 if included_idx else 0)
                                remaining += 1
                                suffix_len = 2 + len(f"+{remaining}")
                        plain_lbl = ", ".join(label_list[i] for i in included_idx)
                        colored_lbl = ", ".join(f"{label_color(file_list[i])}{label_list[i]}{C.X}" for i in included_idx)
                        if remaining > 0:
                            plain_lbl += f", +{remaining}"
                            colored_lbl += f"{C.DM}, {C.Y}+{remaining}{C.X}"

                    right_len = len(plain_lbl)
                    dots = " " + "·" * max(WIDTH - left_len - right_len - 2, 1) + " "
                    print(f"  {C.DM}{tree_prefix}{cred_prefix}{C.X} {C.W}{cred.down_level_logon_name}{C.X}{C.DM}{dots}{C.X}{colored_lbl}")
                else:
                    not_notable = "(not a target)"
                    dots = " " + "·" * max(WIDTH - left_len - len(not_notable) - 2, 1) + " "
                    print(f"  {C.DM}{tree_prefix}{cred_prefix} {cred.down_level_logon_name}{dots}{C.X}{C.G}{not_notable}{C.X}")

            # Empty line between groups (except after last)
            if not is_last_group:
                print(f"  {C.DM}│{C.X}")

        # Summary of other shared passwords (non-notable accounts)
        other_shared = {h: creds for h, creds in shared_hashes.items()
                        if not any(is_notable(c) for c in creds)}
        if other_shared:
            other_users = sum(len(creds) for creds in other_shared.values())
            print()
            print(f"  {C.DM}+ {len(other_shared)} non-target groups ({other_users} users) also share passwords{C.X}")

    # ==========================================================================
    # Cross-Domain Shared Passwords
    # ==========================================================================
    # Find NT hashes present in more than one domain (excludes machine accounts and null hashes)
    cross_domain_hashes: dict[str, list] = {}
    for h, creds in hash_to_creds.items():
        domains = {c.domain.upper() for c in creds if c.domain and not c.is_machine}
        if len(domains) > 1:
            cross_domain_hashes[h] = [c for c in creds if c.domain and not c.is_machine]

    if cross_domain_hashes:
        total_xd_accounts = sum(len(c) for c in cross_domain_hashes.values())
        header("Cross-Domain Shared Passwords", f"{C.R}{len(cross_domain_hashes)}{C.X} groups, {total_xd_accounts} accounts")

        sorted_xd = sorted(cross_domain_hashes.items(), key=lambda x: -len(x[1]))
        for grp_idx, (hash_val, creds) in enumerate(sorted_xd):
            is_last_grp = (grp_idx == len(sorted_xd) - 1)
            grp_prefix = "└─" if is_last_grp else "├─"
            domains = sorted({c.domain.upper() for c in creds})
            cleartext = next((c.cleartext for c in creds if c.is_cracked), "")

            if cleartext:
                pwd_display = redact(cleartext)
                pwd_visible = 12 if (args.redact or args.redact_partial) else len(cleartext)
            else:
                hash_display = redact(hash_val, color=False) if (args.redact or args.redact_partial) else hash_val
                pwd_display = f"{C.O}{hash_display} (not cracked){C.X}"
                pwd_visible = (12 if (args.redact or args.redact_partial) else len(hash_val)) + len(" (not cracked)")

            domain_str = f"{len(domains)} domains, {len(creds)} accounts"
            left_len = 5 + pwd_visible
            dots = " " + "·" * max(WIDTH - left_len - len(domain_str) - 2, 1) + " "
            print(f"  {C.DM}{grp_prefix}{C.X} {pwd_display}{C.DM}{dots}{C.X}{C.Y}{domain_str}{C.X}")

            tree_prefix = "   " if is_last_grp else "│  "
            sorted_creds = sorted(creds, key=lambda c: (c.domain.upper(), c.down_level_logon_name))
            for cred_idx, cred in enumerate(sorted_creds):
                is_last_cred = (cred_idx == len(sorted_creds) - 1)
                cred_prefix = "└─" if is_last_cred else "├─"
                domain_tag = f"{C.DM}[{cred.domain.upper()}]{C.X} "
                name_color = C.R if cred.is_target else ""
                name_reset = C.X if cred.is_target else ""
                print(f"  {C.DM}{tree_prefix}{cred_prefix}{C.X} {domain_tag}{name_color}{cred.down_level_logon_name}{name_reset}")

            if not is_last_grp:
                print(f"  {C.DM}│{C.X}")

    # ==========================================================================
    # Password Analysis
    # ==========================================================================
    cracked_passwords = [c.cleartext for c in all_credentials if c.is_cracked and c.cleartext and not c.is_history]
    if cracked_passwords:
        unique_passwords = list(set(cracked_passwords))
        header("Password Analysis", f"{C.G}{len(unique_passwords)}{C.X} unique passwords")

        # ── Username in Password ──
        username_in_pwd_creds = [c for c in all_credentials
                                  if c.is_cracked and c.cleartext and c.sam_account_name
                                  and not c.is_history
                                  and c.sam_account_name.lower() in c.cleartext.lower()]
        if username_in_pwd_creds:
            count = len(username_in_pwd_creds)
            if args.redact or args.redact_partial:
                label = "account" if count == 1 else "accounts"
                targeted_creds = [c for c in username_in_pwd_creds if c.is_target]
                if targeted_creds:
                    # Collect all target files
                    target_files_set = set()
                    for c in targeted_creds:
                        target_files_set.update(c.target_files)
                    labels = ", ".join(f"{label_color(f)}({target_label(f)}){C.X}" for f in sorted(target_files_set))
                    print(f"  {C.DM}Username in password{C.X}  {C.R}{count}{C.X} {label} — {len(targeted_creds)} in {labels}")
                else:
                    print(f"  {C.DM}Username in password{C.X}  {C.R}{count}{C.X} {label}")
            else:
                print(f"  {C.DM}Username in password{C.X}")
                # Sort with targets first
                sorted_creds = sorted(username_in_pwd_creds, key=lambda c: (not c.is_target, c.sam_account_name.lower()))
                display_creds = sorted_creds[:MAX_DISPLAY]
                remaining = max(0, len(sorted_creds) - MAX_DISPLAY)
                for i, cred in enumerate(display_creds):
                    is_last = (i == len(display_creds) - 1) and remaining == 0
                    prefix = "└─" if is_last else "├─"
                    # Build left side: username and optional target label
                    if cred.is_target:
                        labels = ", ".join(f"{label_color(f)}({target_label(f)}){C.X}" for f in cred.target_files)
                        labels_visible = len(", ".join(f"({target_label(f)})" for f in cred.target_files))
                        left_side = f"{C.W}{cred.sam_account_name}{C.X}  {labels}"
                        left_len = 5 + len(cred.sam_account_name) + 2 + labels_visible
                    else:
                        left_side = f"{C.W}{cred.sam_account_name}{C.X}"
                        left_len = 5 + len(cred.sam_account_name)
                    # Password on right
                    right_len = len(cred.cleartext)
                    dots_len = WIDTH - left_len - right_len
                    dots = " " + "·" * max(dots_len - 2, 1) + " "
                    print(f"  {C.DM}{prefix}{C.X} {left_side}{C.DM}{dots}{C.X}{cred.cleartext}")
                if remaining > 0:
                    print(f"  {C.DM}└─ ... and {remaining} more{C.X}")
            print()

        # ── Length Statistics ──
        lengths = [len(p) for p in cracked_passwords]
        unique_lengths = [len(p) for p in unique_passwords]
        min_len, max_len = min(lengths), max(lengths)
        avg_len = sum(lengths) / len(lengths)
        med_len = median(lengths)

        print(f"  {C.DM}Length{C.X}   min {C.C}{min_len}{C.X}  max {C.C}{max_len}{C.X}  avg {C.C}{avg_len:.1f}{C.X}  median {C.C}{med_len:.0f}{C.X}")

        # ── Length Distribution Histogram ──
        length_counts = {}
        for length in unique_lengths:
            length_counts[length] = length_counts.get(length, 0) + 1

        if length_counts:
            # Only show lengths that have data (sorted)
            lengths_with_data = sorted(length_counts.keys())
            max_count = max(length_counts.values())

            # Calculate column width to fit both bars and labels
            max_label_width = max(len(str(l)) for l in lengths_with_data)
            num_bars = len(lengths_with_data)
            bar_gap = 1

            if num_bars <= 10:
                bar_width = max(3, max_label_width)
            elif num_bars <= 20:
                bar_width = max(2, max_label_width)
            else:
                bar_width = max(1, max_label_width)

            col_width = bar_width + bar_gap

            # Build histogram rows (top to bottom)
            print()
            for row in range(HIST_HEIGHT, 0, -1):
                threshold = (row / HIST_HEIGHT) * max_count
                line = "  "
                for length in lengths_with_data:
                    count = length_counts[length]
                    if count >= threshold:
                        line += f"{C.C}{'█' * bar_width}{C.X} "
                    elif count >= threshold - (max_count / HIST_HEIGHT / 2):
                        line += f"{C.DM}{'▄' * bar_width}{C.X} "
                    elif row == 1 and count > 0:
                        # Ensure outliers with small counts show at least a half-block
                        line += f"{C.DM}{'▄' * bar_width}{C.X} "
                    else:
                        line += " " * col_width
                print(line)

            # X-axis labels (centered under each bar)
            axis_line = "  "
            for length in lengths_with_data:
                label = str(length)
                # Center label under the bar, then add the gap
                axis_line += label.center(bar_width) + " " * bar_gap
            print(f"{C.DM}{axis_line}{C.X}")

        # ── Policy Compliance ──
        if args.policy_length or args.policy_complexity:
            min_length = args.policy_length or 1  # Default to 1 if not specified
            required_classes = args.policy_complexity or 0

            def count_char_classes(pwd):
                """Count character classes present in password"""
                classes = 0
                if any(c.islower() for c in pwd): classes += 1
                if any(c.isupper() for c in pwd): classes += 1
                if any(c.isdigit() for c in pwd): classes += 1
                if any(not c.isalnum() for c in pwd): classes += 1
                return classes

            # Build failure reasons per password
            def get_failures(pwd):
                failures = []
                if args.policy_length and len(pwd) < min_length:
                    failures.append("too_short")
                if args.policy_complexity and count_char_classes(pwd) < required_classes:
                    failures.append("no_complexity")
                return failures

            # Check unique passwords
            passing = []
            failing = []
            fail_reasons = {"too_short": 0, "no_complexity": 0}

            for cred in all_credentials:
                if cred.is_cracked and cred.cleartext:
                    failures = get_failures(cred.cleartext)
                    if failures:
                        failing.append(cred.cleartext)
                        for reason in failures:
                            fail_reasons[reason] += 1
                    else:
                        passing.append(cred.cleartext)

            # Dedupe for display
            unique_passing = len(set(passing))
            unique_failing = len(set(failing))
            total = unique_passing + unique_failing
            if total > 0:
                pass_pct = unique_passing / total * 100
                fail_pct = unique_failing / total * 100

                # Build policy description
                policy_parts = []
                if args.policy_length:
                    policy_parts.append(f"{min_length}+ chars")
                if args.policy_complexity:
                    policy_parts.append(f"{required_classes}-of-4 complexity")

                print()
                print(f"  {C.DM}Policy{C.X}  {', '.join(policy_parts)}")
                print(f"    {C.G}{pass_pct:5.1f}%{C.X}  pass ({unique_passing})")
                # Build fail line with inline reasons
                fail_parts = []
                if fail_reasons["too_short"] > 0:
                    fail_parts.append(f"{fail_reasons['too_short']} too short")
                if fail_reasons["no_complexity"] > 0:
                    fail_parts.append(f"{fail_reasons['no_complexity']} lack complexity")
                fail_detail = f" — {', '.join(fail_parts)}" if fail_parts else ""
                print(f"    {C.R}{fail_pct:5.1f}%{C.X}  fail ({unique_failing}{fail_detail})")

        # ── Character Composition ──
        print()
        print(f"  {C.DM}Composition{C.X}")

        def has_lower(p): return any(c.islower() for c in p)
        def has_upper(p): return any(c.isupper() for c in p)
        def has_digit(p): return any(c.isdigit() for c in p)
        def has_symbol(p): return any(not c.isalnum() for c in p)

        compositions = [
            ("lowercase only", len([p for p in unique_passwords if p.islower()])),
            ("uppercase only", len([p for p in unique_passwords if p.isupper()])),
            ("mixed case", len([p for p in unique_passwords if has_lower(p) and has_upper(p)])),
            ("with digits", len([p for p in unique_passwords if has_digit(p)])),
            ("with symbols", len([p for p in unique_passwords if has_symbol(p)])),
        ]

        for name, count in compositions:
            if count > 0:
                pct = count / len(unique_passwords) * 100
                print(f"    {C.C}{pct:5.1f}%{C.X}  {name}")

        # ── Common Patterns ──
        print()
        print(f"  {C.DM}Patterns{C.X}")

        seasons = r'(spring|summer|fall|autumn|winter)'
        months = r'(january|february|march|april|may|june|july|august|september|october|november|december|jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)'
        patterns = [
            ("starts with capital", len([p for p in unique_passwords if p and p[0].isupper()])),
            ("ends with number", len([p for p in unique_passwords if re.search(r'\d$', p)])),
            ("ends with symbol", len([p for p in unique_passwords if re.search(r'[!@#$%^&*()_+=\-]$', p)])),
            ("contains year (19xx/20xx)", len([p for p in unique_passwords if re.search(r'(19|20)\d{2}', p)])),
            ("contains month name", len([p for p in unique_passwords if re.search(months, p.lower())])),
            ("contains season", len([p for p in unique_passwords if re.search(seasons, p.lower())])),
            ("keyboard walk", len([p for p in unique_passwords if re.search(r'(qwert|asdf|zxcv|1234|!@#\$)', p.lower())])),
        ]

        for name, count in patterns:
            if count > 0:
                pct = count / len(unique_passwords) * 100
                print(f"    {C.C}{pct:5.1f}%{C.X}  {name}")

        # ── Year Distribution ──
        year_counts = {}
        for pwd in unique_passwords:
            years = re.findall(r'((?:19|20)\d{2})', pwd)
            for year in years:
                year_int = int(year)
                if 1980 <= year_int <= 2030:  # Reasonable year range
                    year_counts[year] = year_counts.get(year, 0) + 1

        if year_counts:
            print()
            print(f"  {C.DM}Years found{C.X}")
            max_year_count = max(year_counts.values())
            sorted_years = sorted(year_counts.items(), key=lambda x: -x[1])[:MAX_DISPLAY]
            for year, count in sorted_years:
                pct = count / len(unique_passwords) * 100
                bar_width = max(1, int(BAR_MAX_WIDTH * count / max_year_count))
                bar = f"{C.C}{'█' * bar_width}{C.X}"
                print(f"    {C.C}{year:>6}{C.X}  {bar}  {pct:.0f}%")
            remaining_years = len(year_counts) - len(sorted_years)
            if remaining_years > 0:
                print(f"    {C.DM}... and {remaining_years} more{C.X}")

        # ── Top Passwords ──
        if not args.redact:
            password_freq = {}
            for p in cracked_passwords:
                password_freq[p] = password_freq.get(p, 0) + 1
            top_passwords = sorted(password_freq.items(), key=lambda x: -x[1])[:10]
            reused = [(p, c) for p, c in top_passwords if c > 1]

            if reused:
                print()
                print(f"  {C.DM}Most reused{C.X}")
                for pwd, count in reused:
                    display_pwd = redact(pwd) if args.redact_partial else pwd
                    print(f"    {C.C}{count:5.0f}{C.X}x  {display_pwd}")

        # ── Common Base Words ──
        base_words = {}
        for pwd in unique_passwords:
            base = re.sub(r'[\d!@#$%^&*()_+=\-]+$', '', pwd.lower())
            base = re.sub(r'^[\d!@#$%^&*()_+=\-]+', '', base)  # Strip leading too
            if base and len(base) >= 3:
                base_words[base] = base_words.get(base, 0) + 1

        if base_words:
            top_bases = sorted(base_words.items(), key=lambda x: -x[1])[:10]
            duplicates = [(base, count) for base, count in top_bases if count > 1]
            if duplicates:
                print()
                print(f"  {C.DM}Common bases{C.X}")
                for base, count in duplicates:
                    print(f"    {C.C}{count:5.0f}{C.X}x  {base}")


    # ==========================================================================
    # Export
    # ==========================================================================
    if args.output:
        header("Export")
        output_dir = Path(args.output)
        try:
            output_dir.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            error(f"Failed to create output directory: {e}")
            sys.exit(1)

        files_saved = []

        try:
            # Cracked credentials (simple user:pass format)
            userpass_file = output_dir / "tt-cracked.txt"
            cracked_creds = [c for c in all_credentials if c.is_cracked]
            with open(userpass_file, "w") as f:
                for cred in sorted(cracked_creds):
                    f.write(f"{cred.down_level_logon_name}:{redact(cred.cleartext, color=False)}\n")
            files_saved.append((userpass_file.name, f"{len(cracked_creds)} credentials"))

            # Empty password accounts (critical finding)
            if empty_password_users:
                empty_file = output_dir / "tt-empty-passwords.txt"
                with open(empty_file, "w") as f:
                    for cred in sorted(empty_password_users):
                        f.write(f"{cred.down_level_logon_name}\n")
                files_saved.append((empty_file.name, f"{len(empty_password_users)} accounts"))

            # LM hash accounts (security finding)
            if lm_users:
                lm_file = output_dir / "tt-lm-hashes.txt"
                with open(lm_file, "w") as f:
                    for cred in sorted(lm_users):
                        f.write(f"{cred.down_level_logon_name}:{cred.lm_hash}\n")
                files_saved.append((lm_file.name, f"{len(lm_users)} accounts"))

            # Full CSV export (all credentials with metadata)
            csv_file = output_dir / "tt-all.csv"
            non_history = [c for c in all_credentials if not c.is_history]
            with open(csv_file, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["domain", "username", "password", "target_file", "lm_hash", "empty", "shared_count"])
                for cred in sorted(non_history):
                    domain = cred.down_level_logon_name.split("\\")[0] if "\\" in cred.down_level_logon_name else ""
                    pwd = redact(cred.cleartext, color=False) if cred.is_cracked else ""
                    target_file = ", ".join(target_label(f) for f in cred.target_files) if cred.is_target else ""
                    shared_count = len(hash_to_creds.get(cred.hash, [])) if cred.hash else 0
                    writer.writerow([
                        domain,
                        cred.sam_account_name,
                        pwd,
                        target_file,
                        "yes" if cred.lm_hash and cred.lm_hash != NULL_LM else "no",
                        "yes" if cred.nt_hash == NULL_NT else "no",
                        shared_count if shared_count > 1 else "",
                    ])
            files_saved.append((csv_file.name, f"{len(non_history)} rows"))

            # Password history export
            all_history_creds = [c for c in all_credentials if c.is_history]
            if all_history_creds:
                # Build per-account history map (all history entries, not just cracked)
                hist_by_base: dict[str, list] = {}
                for c in all_history_creds:
                    base_key = f"{c.domain}\\{c.history_base}" if c.domain else c.history_base
                    hist_by_base.setdefault(base_key, []).append(c)

                # Build lookup for current (non-history) accounts by down_level_logon_name
                current_lookup: dict[str, "Credential"] = {
                    c.down_level_logon_name.lower(): c
                    for c in all_credentials if not c.is_history and not c.is_machine
                }

                # Assemble per-account entries with analysis
                # Each entry: (base_key, current_cred|None, hist_sorted, patterns, tier)
                # tier: 0=high-priv, 1=target, 2=other
                account_entries = []
                for base_key, hist_list in hist_by_base.items():
                    hist_sorted = sorted(hist_list, key=lambda c: c.history_index)
                    # Only include if at least one entry (current or history) is cracked
                    current = current_lookup.get(base_key.lower())
                    any_cracked = (current and current.is_cracked) or any(h.is_cracked for h in hist_sorted)
                    if not any_cracked:
                        continue

                    cracked_pwds = []
                    if current and current.is_cracked:
                        cracked_pwds.append(current.cleartext)
                    cracked_pwds += [h.cleartext for h in hist_sorted if h.is_cracked]

                    patterns = []
                    reuse = (current and current.hash and
                             any(h.hash == current.hash for h in hist_sorted))
                    if reuse:
                        patterns.append("PASSWORD REUSE")
                    if detect_incremental(cracked_pwds):
                        patterns.append("INCREMENTAL ROTATION")

                    # Tier: 0=privileged (RID or BloodHound), 1=target file, 2=everyone else
                    if current and (current.priv_label or current.bh_groups):
                        tier = 0
                        tier_label = "PRIVILEGED"
                    elif current and current.is_target:
                        tier = 1
                        tier_label = "TARGET"
                    else:
                        tier = 2
                        tier_label = ""

                    account_entries.append((base_key, current, hist_sorted, patterns, tier, tier_label))

                if account_entries:
                    # Sort: tier asc, then patterns (flagged first), then name
                    account_entries.sort(key=lambda x: (x[4], not bool(x[3]), x[0].lower()))

                    hist_file = output_dir / "tt-history.txt"
                    cracked_hist_count = sum(
                        sum(1 for h in hist_sorted if h.is_cracked)
                        for _, _, hist_sorted, _, _, _ in account_entries
                    )
                    with open(hist_file, "w") as f:
                        current_tier = -1
                        for base_key, current, hist_sorted, patterns, tier, tier_label in account_entries:
                            # Tier section header
                            if tier != current_tier:
                                current_tier = tier
                                if tier == 0:
                                    f.write("=" * 60 + "\n")
                                    f.write("PRIVILEGED ACCOUNTS\n")
                                    f.write("=" * 60 + "\n\n")
                                elif tier == 1:
                                    f.write("=" * 60 + "\n")
                                    f.write("TARGET ACCOUNTS\n")
                                    f.write("=" * 60 + "\n\n")
                                else:
                                    f.write("=" * 60 + "\n")
                                    f.write("OTHER ACCOUNTS\n")
                                    f.write("=" * 60 + "\n\n")

                            # Account header
                            f.write(f"[{base_key}]\n")

                            # Privilege context
                            if current:
                                if current.priv_label:
                                    f.write(f"  RID Role: {current.priv_label}\n")
                                if current.bh_groups:
                                    f.write(f"  Groups  : {', '.join(current.bh_groups)}\n")
                                if current.is_target:
                                    f.write(f"  Target  : {', '.join(target_label(tf) for tf in current.target_files)}\n")

                            # Patterns detected
                            if patterns:
                                f.write(f"  Patterns: {', '.join(patterns)}\n")

                            f.write("\n")

                            # Current password
                            if current:
                                pwd_str = redact(current.cleartext, color=False) if current.is_cracked else "(not cracked)"
                                f.write(f"  current   : {pwd_str}\n")

                            # History entries
                            for h in hist_sorted:
                                pwd_str = redact(h.cleartext, color=False) if h.is_cracked else "(not cracked)"
                                reuse_tag = " [REUSE]" if (h.hash == current.hash if current else False) else ""
                                f.write(f"  history{h.history_index:<3}: {pwd_str}{reuse_tag}\n")

                            f.write("\n")

                    files_saved.append((hist_file.name, f"{len(account_entries)} accounts, {cracked_hist_count} cracked history entries"))
        except OSError as e:
            error(f"Failed to write output file: {e}")
            sys.exit(1)

        if _tee_file:
            files_saved.insert(0, ("tt-output.txt", "full terminal output"))

        # Print saved files as tree
        print(f"  {C.G}Saved to {output_dir}/{C.X}")
        for i, (filename, desc) in enumerate(files_saved):
            is_last = (i == len(files_saved) - 1)
            prefix = "└─" if is_last else "├─"
            print(f"  {C.DM}{prefix}{C.X} {filename}  {C.DM}{desc}{C.X}")

        # Close tee after summary so the full output including this block is captured
        if _tee_file:
            sys.stdout = sys.stdout._real
            _tee_file.close()
    else:
        # Hint about exporting
        print()
        print(f"{C.DM}Tip: Use --output <dir> to export results to files{C.X}")

    print()


if __name__ == "__main__":
    main()
