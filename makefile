.PHONY: setup run clean

# Create a virtual environment and install dependencies
setup:
	python3 -m venv .venv
	./.venv/bin/pip install -r requirements.txt

# Run the main script using the virtual environment
run: setup
	./.venv/bin/python tattletale.py

# Clean up by removing the virtual environment directory
clean:
	rm -rf .venv
