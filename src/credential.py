class Credential():

	def __init__(self):
		# Username formats
		self.down_level_logon_name = ""
		self.sam_account_name = ""
		self.user_principal_name = ""

		# Account Type
		self.is_user_account = True # Default to user account
		self.is_machine_account = False

		# Domain
		self.domain = ""
		self.domain_netbios = ""

		# Secrets
		self.hashtext = ""
		self.cleartext = ""
		self.lm_hashtext = ""
		self.nt_hashtext = ""
		
		# Target ?
		self.is_target = False
		self.target_filenames = []

		# Secrets metadata
		self.is_hash_type_lm = False
		self.is_hash_type_nt = False
		self.is_hash_type_both = False
		self.is_hash_null = False
		self.is_cracked = False

		# Constants
		self.null_hash_lm = "aad3b435b51404eeaad3b435b51404ee"
		self.null_hash_nt = "31d6cfe0d16ae931b73c59d7e0c089c0"

	# For sorting
	def __lt__(self, other):
		# If both are targets, sort by names
		if self.is_target and other.is_target:
			return self.down_level_logon_name < other.down_level_logon_name

		# If the first one is a target, return True
		if self.is_target:
			return True

		# If the other one is a target, return False
		if other.is_target:
			return False

		# If neither are targets, sort by names
		return self.down_level_logon_name < other.down_level_logon_name

	# For hashing
	def __hash__(self):
		return hash(self.down_level_logon_name + ":" + self.hashtext)

	def fill_with_username(self, username):
		# Basic assignments
		self.down_level_logon_name = username

		# Check for machine account
		if username.strip().endswith('$'):
			self.is_machine_account = True
		self.is_user_account = not self.is_machine_account

		# Try to extract the domain
		try:
			username_list = self.down_level_logon_name.split('\\')
			if len(username_list) > 1:
				self.domain = username_list[0].strip()
			self.sam_account_name = username_list[1].strip()
			self.user_principal_name = self.sam_account_name + "@" + self.domain
		except Exception as e:
			self.sam_account_name = self.down_level_logon_name

	def fill_from_dit(self, down_level_logon_name, lm_hashtext, nt_hashtext):
		# Basic assignments
		self.down_level_logon_name = down_level_logon_name
		self.lm_hashtext = lm_hashtext
		self.nt_hashtext = nt_hashtext

		# Check for machine account
		if self.down_level_logon_name.strip().endswith('$'):
			self.is_machine_account = True
		self.is_user_account = not self.is_machine_account

		# Extract the domain
		try:
			username_list = self.down_level_logon_name.split('\\')
			if len(username_list) > 1:
				self.domain = username_list[0].strip()
			self.sam_account_name = username_list[1].strip()
		except Exception as e:
			self.sam_account_name = self.down_level_logon_name

		# Fill UPN using domain
		self.user_principal_name = self.sam_account_name + "@" + self.domain

		# Check for Null hashes
		if (self.lm_hashtext == self.null_hash_lm and self.nt_hashtext == self.null_hash_nt):
			self.is_hash_null = True

		# Check hash type for LM
		if (self.lm_hashtext != self.null_hash_lm):
			self.is_hash_type_lm = True
			self.is_hash_null = False
			self.hashtext = self.lm_hashtext
		
		# Check hash type for nt
		if (self.nt_hashtext != self.null_hash_nt):
			self.is_hash_type_nt = True
			self.is_hash_null = False
			self.hashtext = self.nt_hashtext

		# Both nt and LM present?
		if (self.is_hash_type_lm and self.is_hash_type_nt):
			self.is_hash_type_both = True

	def crack(self, cleartext):
		self.cleartext = cleartext

		# Don't consider null hashes "cracked"
		if (len(self.cleartext) > 0):
			self.is_cracked = True