# TattleTale

![TattleTale Logo](https://raw.githubusercontent.com/coryavra/tattletale/master/images/logo.png)

## Description

TattleTale is an open-source tool designed to analyze and reveal secrets from NTDS.dit dumpfiles. It is intended to be used by penetration testers and cybersecurity professionals in the post-exploitation phase, or also by IT professionals who want to audit their Active Directory environment.

## Installation

Download the source code with git, and use the makefile to initialize a Python virtual environment with the required dependencies:

```
make
```

Then run with:

```
./tattletale.py -d DITFILES [DITFILES ...] [-p POTFILES [POTFILES ...]] [-t TARGETFILES [TARGETFILES ...]] [-o OUTPUT]
```

Each flag can take multiple arguments. Here's an example that analyzes 2 ditfiles and 2 target files:

```
./tattletale.py --ditfiles ntds1.dit ntds2.dit -potfiles hashes.pot --targetfiles domain_admins.txt enterprise_admins.txt
```