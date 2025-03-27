# Imports
import os
import time
import logging
import datetime
import csv

import scrikit
from . import dit_file
from . import pot_file
from . import target_file
from . import credential

class HashEngine():

	def __init__(self):
		logging.info("Initializing Hash Engine...")

		# Files
		self.dit_files = [] # List of dit file objects
		self.pot_files = [] # List of pot file objects
		self.target_files = [] # List of target file objects

		# Credentials
		self.credentials = [] # List of combined credential objects
		self.shared_hashes_to_export = {} # hash:[cred]

	def digest_ditfiles(self, files):
		for filepath in files:
			logging.info("Digesting ntds.dit file: " + scrikit.theme.text_file + filepath + scrikit.theme.reset)

			try:
				f = dit_file.DitFile()
				f.digest(filepath)
				self.dit_files.append(f)
			except FileNotFoundError:
				logging.error("No such file: " + scrikit.theme.text_file + filepath)

	def digest_potfiles(self, files):
		for filepath in files:
			logging.info("Digesting pot file: " + scrikit.theme.text_file + filepath + scrikit.theme.reset)

			try:
				f = pot_file.PotFile()
				f.digest(filepath)
				self.pot_files.append(f)
			except FileNotFoundError:
				logging.error("No such file: " + scrikit.theme.text_file + filepath)

	def digest_targets(self, files):
		for filepath in files:
			logging.info("Digesting target file: " + scrikit.theme.text_file + filepath + scrikit.theme.reset)

			try:
				f = target_file.TargetFile()
				f.digest(filepath)
				self.target_files.append(f)
			except FileNotFoundError:
				logging.error("No such file: " + scrikit.theme.text_file + filepath)

	def analyze(self):
		self.check_for_cracked_hashes()
		self.gather_credentials()
		self.calculate_statistics()

	def check_for_cracked_hashes(self):
		logging.info("Checking potfile(s) for cracked hashes for every user in ditfile(s)...")
		for dit in self.dit_files:
			for pot_file in self.pot_files:
				for cred in dit.credentials:
					if cred.hashtext in pot_file.hashes.keys():
						cleartext = pot_file.hashes[cred.hashtext]
						cred.crack(cleartext)

	def gather_credentials(self):
		logging.info("Gathering credentials...")

		# Gather every credential from every dit file
		for dit in self.dit_files:
			for cred in dit.credentials:
				self.credentials.append(cred)
				# scrikit.overwritable_message("Digested " + str(len(self.credentials)) + ' credentials')

		# Remove duplicates
		self.credentials = list(dict.fromkeys(self.credentials))

		# Check for targets / admins
		for file in self.target_files:
			for target_name in file.targets:
				found = False

				# Check to see if the target exists from the dit file
				for cred in self.credentials:

					# Only compare the sam account name - ignore domain for now
					if cred.sam_account_name.lower() == target_name.lower():
						cred.is_target = True
						cred.target_filenames.append(file.filename)
						found = True

				# Add the target even if they don't exist in the dit
				if not found:
					logging.warning(f"User in targetfile not found in ditfile(s): {scrikit.theme.text_person}{target_name}{scrikit.theme.reset}")
					new_cred = credential.Credential()
					new_cred.fill_with_username(target_name)
					new_cred.is_target = True
					new_cred.target_filenames.append(file.filename)
					self.credentials.append(new_cred)

	def calculate_statistics(self):
		logging.info("Analyzing all hashes..")

		# If there is more than one dit file, add a psuedo "conglomerated" dit file to the list
		if len(self.dit_files) > 1:
			f = dit_file.DitFile()
			f.filename = "Combined Dit Files"
			f.credentials = self.credentials
			self.dit_files.append(f)

		# Individual dit file statistics
		for dit in self.dit_files:
			dit.calculate_statistics()

	def show_results(self):
		if (not self.dit_files):
			logging.error("No dit files to analyze")
		else:
			# Construct the table header and formatting
			t = scrikit.Tree()
			t.width = 100
			t.print_title("TattleTale: Domain Secrets (NTDS) Analysis Results")

			# Start with basic statistics for each dit file)
			t.print_header(1, "Password Hash Statistics")
			for dit in self.dit_files:

				t.print_header(2, "Analaysis of " + dit.filename)

				# Basic facts
				t.print_row("Total hashes", str(len(dit.credentials)))
				t.print_row("All User Hashes", str(dit.statistics['user']['all_count']))
				t.print_row("All Machine Hashes", str(dit.statistics['machine']['all_count']))
				t.print_row("Removable Empty Hashes", str(dit.statistics['null']['all_count']))
				t.print_row("No-Domain Hashes", str(dit.statistics['no_domain']['all_count']))
				t.print_row("Remaining User Hashes", str(dit.statistics['valid_domain_user']['all_count']))

				# Categorized cracking facts
				hash_types = ['valid_domain_user', 'no_domain', 'lm', 'nt']
				for hash_type in hash_types:
					t.print_header(3, hash_type.replace('_', ' ').title() + ' Hashes')
					t.print_row("All", str(dit.statistics[hash_type]['all_count']))
					t.print_row("Cracked", str(dit.statistics[hash_type]['cracked_count']))
					t.print_row("Cracked Percentage", dit.statistics[hash_type]['cracked_percentage'])
					t.print_row("Unique", str(dit.statistics[hash_type]['unique_count']))
					t.print_row("Cracked Unique", str(dit.statistics[hash_type]['unique_cracked_count']))
					t.print_row("Cracked Unique Percentage", dit.statistics[hash_type]['unique_cracked_percentage'])

			# Show stats for shared password hashes across domains and services
			t.print_header(1, "High-Value Targets")

			# Gather credentials and organize them by their target filename
			creds_by_target_file = {} # target_filename : [target_cred]
			for cred in self.credentials:

					if cred.is_target:

						for target_file in cred.target_filenames:

							if not target_file in creds_by_target_file.keys():
								creds_by_target_file[target_file] = []
							creds_by_target_file[target_file].append(cred)

			# For each identified target file
			for target_file in creds_by_target_file:

				# Organize associated users
				cracked_users = []
				uncracked_users = []
				for cred in creds_by_target_file[target_file]:

					if cred.is_cracked:
						cracked_users.append(cred)
					else:
						uncracked_users.append(cred)

				t.print_header(2, target_file, str(len(cracked_users)) + ' / ' + str(len(cracked_users) + len(uncracked_users)))
				
				cracked_users.sort()
				uncracked_users.sort()

				# Display users
				for cred in cracked_users:
					t.print_row(cred.down_level_logon_name, scrikit.ansi.set_fg_color(196) + cred.cleartext + scrikit.theme.reset)
				for cred in uncracked_users:
					t.print_row(cred.down_level_logon_name, scrikit.ansi.set_fg_color(27) + "(Not cracked)" + scrikit.theme.reset)

			# Show stats for shared password hashes across domains and services
			t.print_header(1, f"Shared Password Hashes {scrikit.theme.text_file}(with at least 1 high-value target){scrikit.theme.reset}")
			shared_hashes = {} # hash:[cred]
			shared_target_hashes = {}
			for cred in self.credentials:

				if not cred.is_hash_null:
					if not cred.hashtext in shared_hashes.keys():
						shared_hashes[cred.hashtext] = []
					shared_hashes[cred.hashtext].append(cred)

			for hash in shared_hashes:

				# If there is more than one user using this password...
				if len(shared_hashes[hash]) > 1:

					# If at least one user is a target...
					used_by_admin = False
					for cred in shared_hashes[hash]:
						if cred.is_target:
							used_by_admin = True

					if used_by_admin:

						# If cracked
						if shared_hashes[hash][0].is_cracked:
							t.print_header(2, shared_hashes[hash][0].hashtext + ' - ' + f'{scrikit.ansi.set_fg_color(197)}{cred.cleartext}{scrikit.theme.reset}', str(len(shared_hashes[hash])) + " Accounts")
						else:
							t.print_header(2, shared_hashes[hash][0].hashtext + ' - (Not Cracked)', str(len(shared_hashes[hash])) + " Accounts")

						# Display users
						shared_hashes[hash].sort()
						for cred in shared_hashes[hash]:

							if cred.is_target:
								t.print_row(cred.down_level_logon_name, scrikit.ansi.set_fg_color(196) + ', '.join(cred.target_filenames) + scrikit.theme.reset)
							else:
								t.print_row(cred.down_level_logon_name, scrikit.ansi.set_fg_color(27) + "(Not a target)" + scrikit.theme.reset)

			# Show stats for shared password hashes across domains and services
			t.print_header(1, f"Shared Password Hashes {scrikit.theme.text_file}(All cases! Not necessarily shared with an admin){scrikit.theme.reset}")
			shared_hashes = {} # hash:[cred]
			shared_target_hashes = {}
			for cred in self.credentials:

				if not cred.is_hash_null:
					if not cred.hashtext in shared_hashes.keys():
						shared_hashes[cred.hashtext] = []
					shared_hashes[cred.hashtext].append(cred)

			for hash in shared_hashes:

				# If there is more than one user using this password...
				if len(shared_hashes[hash]) > 1:

					# Add it to the dictionary to export, with all of the attached creds
					self.shared_hashes_to_export[hash] = shared_hashes[hash]

					# If cracked
					if shared_hashes[hash][0].is_cracked:
						t.print_header(2, shared_hashes[hash][0].hashtext + ' - ' + f'{scrikit.ansi.set_fg_color(197)}{cred.cleartext}{scrikit.theme.reset}', str(len(shared_hashes[hash])) + " Accounts")
					else:
						t.print_header(2, shared_hashes[hash][0].hashtext + ' - (Not Cracked)', str(len(shared_hashes[hash])) + " Accounts")

					# Display users
					shared_hashes[hash].sort()
					for cred in shared_hashes[hash]:

						if cred.is_target:
							t.print_row(cred.down_level_logon_name, scrikit.ansi.set_fg_color(196) + ', '.join(cred.target_filenames) + scrikit.theme.reset)
						else:
							t.print_row(cred.down_level_logon_name, scrikit.ansi.set_fg_color(27) + "(Not a target)" + scrikit.theme.reset)

	def save_shared_hashes(self, output_directory):
		ts = time.time()
		formatted_ts = datetime.datetime.fromtimestamp(ts).strftime('%Y.%m.%d_%H.%M.%S')

		# Create a new csv file in the specified output directory
		outbox = output_directory
		filepath = os.path.expanduser(os.path.join(outbox, 'tattletale_shared_hashes_' + formatted_ts + '.csv'))

		try:
			with open(filepath, mode='w', newline='') as csvfile:
				writer = csv.writer(csvfile)

				# Write the header
				writer.writerow(['Hash', 'Username'])

				# Write the data rows
				for hash_value, usernames in self.shared_hashes_to_export.items():
					for username in usernames:
						writer.writerow([hash_value, username.down_level_logon_name])
			logging.info("Shared hashes saved to " + scrikit.theme.text_file + filepath)
		except Exception as e:
			logging.error("Error saving file: " + str(e))
			print("Tip: Check if the output directory exists and is writable")

	def save_user_pass(self, output_directory):
		ts = time.time()
		formatted_ts = datetime.datetime.fromtimestamp(ts).strftime('%Y.%m.%d_%H.%M.%S')

		# Create a new csv file in the specified output directory
		outbox = output_directory
		filepath = os.path.expanduser(os.path.join(outbox, 'tattletale_user_pass_' + formatted_ts + '.txt'))
		try:
			with open(filepath, 'w') as f:
				for cred in self.credentials:
					if cred.is_cracked:
						f.write(cred.down_level_logon_name + ':' + cred.cleartext + '\n')
			f.close()
			logging.info("User:pass saved to " + scrikit.theme.text_file + filepath)
		except Exception as e:
			logging.error("Error saving file: " + str(e))
			print("Tip: Check if the output directory exists and is writable")
