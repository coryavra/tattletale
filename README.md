# TattleTale

Post-exploitation NTDS dump analyzer for penetration testing. Analyzes secretsdump output, correlates with hashcat potfiles, and identifies password reuse across accounts.

## Features

- Parses multiple DIT files (multi-domain analysis)
- Correlates with hashcat potfiles
- Identifies high-value targets (domain admins, service accounts)
- Detects shared password hashes across accounts
- Password pattern analysis (seasons, months, years, common bases)
- Statistics: cracking rates, LM vs NT, unique hashes
- Exports cracked credentials and shared hash reports
- Redaction options for sharing reports

## Installation

### Python (Recommended)

Standalone Python 3.10+ with no external dependencies.

```bash
# Run directly
python3 tattletale.py -d ntds.dit -p cracked.pot

# Or make executable
chmod +x tattletale.py
./tattletale.py -d ntds.dit -p cracked.pot
```

### Containers

The included `Containerfile` is OCI-compatible and works with both Docker and Apple Containers.

**Docker:**

```bash
docker build -t tattletale .

docker run --rm -v "$(pwd)/data:/mnt/shared" tattletale \
    python3 tattletale.py \
    -d /mnt/shared/ntds.dit \
    -p /mnt/shared/cracked.pot \
    -o /mnt/shared/report
```

**Apple Containers (macOS 26+):**

```bash
container build --tag tattletale .

container run --rm \
    --volume /tmp/container/tattletale:/mnt/shared \
    tattletale \
    python3 tattletale.py \
    -d /mnt/shared/ntds.dit \
    -p /mnt/shared/cracked.pot
```

### Makefile

The `Makefile` is for **Apple Containers only** (macOS 26+ with the native containerization framework). It provides convenience targets for building, running, and managing containers.

```bash
make build    # Build the container image
make run      # Build and run interactively (files in /tmp/container/tattletale/)
make test     # Run unit tests
make clean    # Remove image and prune resources
make help     # Show all targets
```

## Usage

```
USAGE
    tattletale -d <ditfile> [-p <potfile>] [-t <targets>] [options]

REQUIRED
    -d, --ditfiles <file>...    NTDS.DIT dump file(s) from secretsdump

OPTIONS
    -p, --potfiles <file>...    Hashcat potfile(s) with cracked hashes
    -t, --targetfiles <file>... Target lists (domain admins, service accounts)
    -o, --output <dir>          Export reports to directory
    --redact-full               Hide passwords completely (********)
    --redact-partial            Show first two chars only (Pa******)
    -q, --quiet                 Suppress banner and status messages
    -h, --help                  Show help message
```

## Examples

```bash
# Basic analysis
python3 tattletale.py -d ntds.dit

# With cracked hashes
python3 tattletale.py -d ntds.dit -p hashcat.potfile

# Full analysis with targets and export
python3 tattletale.py -d ntds.dit -p cracked.pot -t domain_admins.txt -o ./report

# Redacted output for client reports
python3 tattletale.py -d ntds.dit -p cracked.pot --redact-partial -o ./report

# Run with example data
python3 tattletale.py -d examples/sample.dit -p examples/sample.pot -t examples/targets.txt
```

## Input Formats

| File Type | Format | Example |
|-----------|--------|---------|
| DIT dump | secretsdump output | `DOMAIN\user:1001:LM_HASH:NT_HASH:::` |
| Potfile | hashcat potfile | `NT_HASH:cleartext` |
| Targets | one username per line | `administrator` |

## Output

The tool produces:

- **Statistics**: Account counts, cracking progress, hash types
- **High Value Targets**: Status of priority accounts (if target file provided)
- **Shared Credentials**: Accounts sharing the same password hash
- **Password Analysis**: Common patterns, base words, length distribution
- **Export Files**: `cracked_credentials.txt` and `shared_hashes.txt`

## Testing

```bash
# Run unit tests
python3 tests/test_tattletale.py

# Or via Makefile (Apple Containers)
make test
```

## License

MIT
