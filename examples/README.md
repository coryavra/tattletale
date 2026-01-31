# Example Data

Sample files for testing TattleTale. All data is synthetic - no real credentials.

## Files

| File | Description |
|------|-------------|
| `sample.dit` | Fake NTDS dump with domain admins, service accounts, regular users, and machine accounts |
| `sample.pot` | Hashcat potfile with "cracked" hashes |
| `targets.txt` | High-value target list (domain admins, service accounts) |

## Usage

```bash
# Basic analysis
python3 tattletale.py -d examples/sample.dit

# With cracked hashes
python3 tattletale.py -d examples/sample.dit -p examples/sample.pot

# Full analysis with targets
python3 tattletale.py -d examples/sample.dit -p examples/sample.pot -t examples/targets.txt

# Export report
python3 tattletale.py -d examples/sample.dit -p examples/sample.pot -t examples/targets.txt -o ./report
```

## Expected Findings

The sample data demonstrates:

- **Shared passwords**: Multiple accounts using the same hash
- **Cracked targets**: Domain admins with weak passwords
- **LM hash**: Legacy account with LM hash present (security finding)
- **Empty passwords**: Guest and disabled accounts with null hashes
