#!/usr/bin/env python3

# Dunder (double-underscore) Variables
__doc__ = "A post-exploitation NTDS dumpfile reporter / the worst secret-keeper ever"
__version__ = "2.0.0"
__title__ = "TattleTale"
__author__ = "@coryavra"
__url__ = "https://github.com/coryavra/tattletale"
__license__ = "MIT"

# Imports
import scrikit
from src.hash_engine import HashEngine

# Initialize script
script = scrikit.Script()

# Argument parsing handled by native argparse, via script instance
script.parser.add_argument("-d", "--ditfiles", help="An NTDS.DIT file", required=True, nargs="+")
script.parser.add_argument("-p", "--potfiles", help="A hashcat potfile with cracked hashes from the dit", nargs="+")
script.parser.add_argument("-t", "--targetfiles", help="A .txt file with a list of targets (domain admins, local admins, etc.)", nargs="+")
script.parser.add_argument("-o", "--output", help="Optional - save a report to the specified output directory")

# Display the banner
script.print_banner(logo_path="banner/logo.txt", title_path="banner/title.txt", tagline="Share secrets; reveal truth")

# Display metadata
script.print_metadata(
	title=__title__,
	author=__author__,
	description=__doc__,
	url=__url__,
	version=__version__,
	license=__license__
)

# Decorated main function
@script.run
def main():

	# Start the engine
	h = HashEngine()

	# Digest arguments
	h.digest_ditfiles(script.arguments["ditfiles"])
	h.digest_potfiles(script.arguments["potfiles"])
	h.digest_targets(script.arguments["targetfiles"])

	# Perform analysis
	h.analyze()
	h.show_results()

	# Save results only if requested
	if script.arguments["output"]:
		print()
		h.save_shared_hashes(script.arguments["output"])
		h.save_user_pass(script.arguments["output"])

if __name__ == "__main__":
	main()