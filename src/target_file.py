class TargetFile():

	def __init__(self):
		self.filename = ""
		self.filepath = ""
		self.targets = [] # List of admin users

	def digest(self, filepath):
		self.filepath = filepath
		self.filename = filepath.split('/')[-1]
		file = open(self.filepath)

		for line in file:
			# Extract username from line
			username = line.strip()

			# Add the username to the list for this file
			if (len(username) > 0):
				self.targets.append(username)

		file.close()