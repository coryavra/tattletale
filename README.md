# TattleTale

[![PyPI version](https://img.shields.io/pypi/v/ntds-tattletale)](https://pypi.org/project/ntds-tattletale/)
[![PyPI downloads](https://img.shields.io/pypi/dm/ntds-tattletale)](https://pypi.org/project/ntds-tattletale/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

![Help](assets/tt_help.png)

Analyze secretsdump output and hashcat potfiles to find shared passwords, weak credentials, and other issues in Active Directory. No dependencies.

Built from years of hands-on experience in enterprise penetration testing. Used in real-world assessments of Fortune 500 companies and critical infrastructure.

## What it does

So you've dumped the NTDS.dit and cracked some hashes, but you're left with a wall of text. TattleTale simply surfaces what the data is hiding:

- **Shared credentials** - IT manager uses the same password for both of his accounts
- **Weak privileged accounts** - 4 domain admins cracked in under an hour
- **Password patterns** - 60% of passwords follow `Season+Year` format
- **Legacy security issues** - service accounts still have LM hashes enabled
- **Empty passwords** - accounts with no password set (often disabled, but verify)
- **Policy violations** - passwords that don't meet length/complexity requirements

It also tracks high-value targets across multiple lists (domain admins, service accounts, executives) so you can see exactly which critical accounts were compromised at a glance, and if any of those accounts are sharing passwords elsewhere...

## Install

### pip

```bash
pip install ntds-tattletale
```

Then run it:

```bash
tattletale -d dump.ntds -p cracked.pot
```

### Standalone

It's a single Python file with no dependencies. Grab it and go:

```bash
curl -O https://raw.githubusercontent.com/coryavra/tattletale/master/tattletale.py
python3 tattletale.py -d dump.ntds -p cracked.pot
```

### Container

The included `Containerfile` works with [Apple Containers](https://github.com/apple/containerization) (macOS 26+) and Docker (OCI-compliant).

```bash
# Apple Containers (native to macOS)
container build -t tattletale .
container run --rm -v "$(pwd)/data:/mnt/shared" tattletale \
    -d /mnt/shared/ntds.dit \
    -p /mnt/shared/cracked.pot \
    -o /mnt/shared/report

# Docker works too
docker build -t tattletale .
docker run --rm -v "$(pwd)/data:/mnt/shared" tattletale \
    -d /mnt/shared/ntds.dit \
    -p /mnt/shared/cracked.pot \
    -o /mnt/shared/report
```

## Usage

```
tattletale -d <file> [-p <file>] [-t <files>] [options]

REQUIRED
    -d, --dit <file>            secretsdump output file

OPTIONS
    -p, --pot <file>            hashcat potfile with cracked hashes
    -t, --targets <files>       target lists (admins.txt, svc.txt, etc)
    -o, --output <dir>          export reports to directory
    -r, --redact-partial        show first 2 chars only (Pa**********)
    -R, --redact-full           hide passwords completely (************)
    -h, --help                  show help message
    -V, --version               show version

POLICY
    --policy-length <n>         minimum password length
    --policy-complexity <n>     require n-of-4 character classes (upper, lower, digit, symbol)
    --policy-no-username        password cannot contain username
```

## Examples

```bash
# Basic analysis - just the dump file
tattletale -d ntds.dit

# With cracked hashes from hashcat
tattletale -d ntds.dit -p hashcat.pot

# Track high-value targets with multiple lists
tattletale -d ntds.dit -p hashcat.pot -t domain_admins.txt svc_accounts.txt

# Redacted output for client reports
tattletale -d ntds.dit -p hashcat.pot -r -o ./report

# Check cracked passwords against policy (8 chars, 3-of-4 complexity)
tattletale -d ntds.dit -p hashcat.pot --policy-length 8 --policy-complexity 3
```

## Output

### Statistics

Overview of the dump: total accounts, cracking progress, hash types, and security warnings like empty passwords or legacy LM hashes.

![Statistics](assets/tt_stats.png)

### High Value Targets

Shows the status of accounts from your target lists. Grouped by file so you can track domain admins separately from service accounts.

![High Value Targets](assets/tt_targets.png)

### Shared Credentials

Accounts that share the same password hash. Grouped by password with target accounts highlighted.

![Shared Credentials](assets/tt_shared_creds.png)

### Password Analysis

Pattern analysis across all cracked passwords: length distribution, character composition, common patterns (seasons, years, keyboard walks), and most reused passwords.

![Password Analysis](assets/tt_analysis.png)

## Input formats

| File | Format | Example |
|------|--------|---------|
| DIT dump | secretsdump output | `DOMAIN\user:1001:LM_HASH:NT_HASH:::` |
| Potfile | hashcat potfile | `NT_HASH:cleartext` |
| Targets | one username per line | `administrator` |

## See also

Standing on the shoulders of giants:

- [secretsdump.py](https://github.com/fortra/impacket) - extract hashes from NTDS.DIT
- [hashcat](https://hashcat.net/hashcat/) - crack the hashes
- [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec) - password spraying and more

## License

MIT
