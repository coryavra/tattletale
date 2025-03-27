class PotFile():

	def __init__(self):
		self.filename = ""
		self.filepath = ""
		self.hashes = {} # Dict of hashtext:cleartext

	def digest(self, filepath):
		self.filepath = filepath
		self.filename = filepath.split('/')[-1]
		file = open(self.filepath)

		for line in file:
			line_list = line.split(":", 1) # Only split once, hash:password
			hashtext = line_list[0].strip()
			cleartext = line_list[1].strip()

			# Add the pot hash to the dictionary for this file
			self.hashes[hashtext] = cleartext

		file.close()