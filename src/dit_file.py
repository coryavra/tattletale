# Imports
from . import credential

class DitFile():

	def __init__(self):
		self.filename = ""
		self.filepath = ""
		self.credentials = [] # List of credential objects
		self.statistics = {}

	def digest(self, filepath):
		self.filepath = filepath
		self.filename = filepath.split('/')[-1]
		file = open(self.filepath)

		for line in file:
			line_list = line.split(":") # username:user_id:LM_hash:NT_hash
			username = line_list[0].strip()
			lm_hashtext = line_list[2].strip()
			nt_hashtext = line_list[3].strip()

			# Create a new credential with the extracted values
			cred = credential.Credential()
			cred.fill_from_dit(username, lm_hashtext, nt_hashtext)
			self.credentials.append(cred)

		file.close()

	# Simple algorithm to evaluate common statistics given a list of creds
	def analyze_creds(self, creds):
		hashes = []
		passwords = []

		for cred in creds:
			hashes.append(cred.hashtext)
			if cred.is_cracked:
				passwords.append(cred.cleartext)

		# Calculate percentages
		if (len(hashes)):
			cracked_percentage = str(round(len(passwords) / len(hashes) * 100, 2)) + '%'
			unique_cracked_percentage = str(round(len(set(passwords)) / len(set(hashes)) * 100, 2)) + '%'
		else:
			cracked_percentage = '0.00%'
			unique_cracked_percentage = '0.00%'

		results = {
			'all_count': len(hashes),
			'cracked_count': len(passwords),
			'cracked_percentage': cracked_percentage,
			'unique_count': len(set(hashes)),
			'unique_cracked_count': len(set(passwords)),
			'unique_cracked_percentage': unique_cracked_percentage
		}

		return results

	def calculate_statistics(self):
		creds_user = []
		creds_machine = []
		creds_valid_user = []
		creds_valid_machine = []
		creds_lm = []
		creds_nt = []
		creds_both = []
		creds_null = []
		creds_no_domain = []

		# Fill lists
		for cred in self.credentials:

			# User accounts
			if (cred.is_user_account):
				creds_user.append(cred)

				# Valid user accounts
				if (not cred.is_hash_null and cred.domain):
					creds_valid_user.append(cred)

			# Machine accounts
			if (cred.is_machine_account):
				creds_machine.append(cred)

				# Valid machine accounts
				if (not cred.is_hash_null):
					creds_valid_machine.append(cred)

			# Ignoring null creds (shouldn't be any if a hash type is set, but just in case)
			if (not cred.is_hash_null):

				# LM
				if (cred.is_hash_type_lm):
					creds_lm.append(cred)

				# NT
				if (cred.is_hash_type_nt):
					creds_nt.append(cred)

				# LM and NT
				if (cred.is_hash_type_both):
					creds_both.append(cred)

			# Null
			if (cred.is_hash_null):
				creds_null.append(cred)

			# No Domain
			if not cred.domain:
				creds_no_domain.append(cred)


		# Fill statistics dictionary
		self.statistics = {
			'user': self.analyze_creds(creds_user),
			'machine': self.analyze_creds(creds_machine),
			"valid_domain_user": self.analyze_creds(creds_valid_user),
			"valid_machine": self.analyze_creds(creds_valid_machine),
			"lm": self.analyze_creds(creds_lm),
			"nt": self.analyze_creds(creds_nt),
			"both": self.analyze_creds(creds_both),
			"null": self.analyze_creds(creds_null),
			"no_domain": self.analyze_creds(creds_no_domain)
		}