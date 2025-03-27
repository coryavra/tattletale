# TattleTale

![TattleTale Logo](https://raw.githubusercontent.com/coryavra/tattletale/master/images/logo.png)

## Description

TattleTale is an open-source tool designed to analyze and reveal secrets from NTDS.dit dumpfiles. It is intended to be used by penetration testers and cybersecurity professionals in the post-exploitation phase, or also by IT professionals who want to audit their Active Directory environment.

## Installation

Run the following commands to download the source code and create a virtual environment:

```
git clone https://github.com/coryavra/tattletale.git
cd tattletale
make
```

Then, activate the virutla environment:
```
source .venv/bin/activate
```

Finally, run with:

```
./tattletale.py -d DITFILES [DITFILES ...] [-p POTFILES [POTFILES ...]] [-t TARGETFILES [TARGETFILES ...]] [-o OUTPUT]
```

Each flag can take multiple arguments. The output flag takes an existing directory, not a filename. Here's an example that analyzes 2 ditfiles and 2 target files:

```
./tattletale.py --ditfiles ntds1.dit ntds2.dit -potfiles hashes.pot --targetfiles domain_admins.txt enterprise_admins.txt --output /path/to/existing/directory
```