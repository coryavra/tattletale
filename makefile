# TattleTale - Apple Containers Makefile
# For macOS 26+ with native containerization framework
# See README.md for Docker usage

IMAGE_NAME := $(notdir $(CURDIR))
HOST_DIR := /tmp/container/$(IMAGE_NAME)
VOLUMES := --volume "$(HOST_DIR):/mnt/shared"

-include container.conf

.DEFAULT_GOAL := help
.PHONY: build run clean test test-unit nuke help

build:
	container build --no-cache --tag "$(IMAGE_NAME)" .

run: build
	@mkdir -p "$(HOST_DIR)"
	@echo "\033[90mFiles: $(HOST_DIR) -> /mnt/shared\033[0m"
	container run --remove --name "$(IMAGE_NAME)" --interactive --tty $(VOLUMES) $(PORTS) $(ENV_VARS) $(EXTRA_FLAGS) "$(IMAGE_NAME)"

clean:
	@container image rm "$(IMAGE_NAME)" 2>/dev/null || true
	@echo "\033[32mRemoved $(IMAGE_NAME) image\033[0m"

test:
	@echo ""
	@echo "\033[1;33m╔══════════════════════════════════════════════════════════════════════╗\033[0m"
	@echo "\033[1;33m║  TEST 1: Basic (DIT only)                                            ║\033[0m"
	@echo "\033[1;33m╚══════════════════════════════════════════════════════════════════════╝\033[0m"
	@echo "\033[36m\$$ python3 tattletale.py --dit examples/sample.dit\033[0m"
	@echo ""
	@python3 tattletale.py --dit examples/sample.dit
	@echo ""
	@echo "\033[1;33m╔══════════════════════════════════════════════════════════════════════╗\033[0m"
	@echo "\033[1;33m║  TEST 2: With cracked hashes                                         ║\033[0m"
	@echo "\033[1;33m╚══════════════════════════════════════════════════════════════════════╝\033[0m"
	@echo "\033[36m\$$ python3 tattletale.py --dit examples/sample.dit --pot examples/sample.pot\033[0m"
	@echo ""
	@python3 tattletale.py --dit examples/sample.dit --pot examples/sample.pot
	@echo ""
	@echo "\033[1;33m╔══════════════════════════════════════════════════════════════════════╗\033[0m"
	@echo "\033[1;33m║  TEST 3: Multiple target files                                       ║\033[0m"
	@echo "\033[1;33m╚══════════════════════════════════════════════════════════════════════╝\033[0m"
	@echo "\033[36m\$$ python3 tattletale.py -d examples/sample.dit -p examples/sample.pot -t examples/domain_admins.txt examples/service_accounts.txt\033[0m"
	@echo ""
	@python3 tattletale.py -d examples/sample.dit -p examples/sample.pot -t examples/domain_admins.txt examples/service_accounts.txt
	@echo ""
	@echo "\033[1;33m╔══════════════════════════════════════════════════════════════════════╗\033[0m"
	@echo "\033[1;33m║  TEST 4: Redacted output (-r)                                        ║\033[0m"
	@echo "\033[1;33m╚══════════════════════════════════════════════════════════════════════╝\033[0m"
	@echo "\033[36m\$$ python3 tattletale.py -d examples/sample.dit -p examples/sample.pot -t examples/domain_admins.txt examples/service_accounts.txt -r\033[0m"
	@echo ""
	@python3 tattletale.py -d examples/sample.dit -p examples/sample.pot -t examples/domain_admins.txt examples/service_accounts.txt -r
	@echo ""
	@echo "\033[1;33m╔══════════════════════════════════════════════════════════════════════╗\033[0m"
	@echo "\033[1;33m║  TEST 5: Policy compliance check                                     ║\033[0m"
	@echo "\033[1;33m╚══════════════════════════════════════════════════════════════════════╝\033[0m"
	@echo "\033[36m\$$ python3 tattletale.py -d examples/sample.dit -p examples/sample.pot --policy-length 12 --policy-complexity 3\033[0m"
	@echo ""
	@python3 tattletale.py -d examples/sample.dit -p examples/sample.pot --policy-length 12 --policy-complexity 3

test-unit:
	@python3 tests/test_tattletale.py 2>&1 && echo "\033[32mAll tests passed\033[0m"

nuke:
	@echo "\033[33mResetting container builder...\033[0m"
	@pkill -9 -f 'buildkit' 2>/dev/null || true
	@sleep 1
	@container builder delete --force 2>/dev/null || true
	@container system start 2>/dev/null || true
	@sleep 1
	@container builder start --memory 4G
	@echo "\033[32mBuilder reset complete\033[0m"

help:
	@echo ""
	@echo "\033[1mUsage:\033[0m make \033[36m[target]\033[0m"
	@echo ""
	@echo "\033[33mTargets:\033[0m"
	@echo "  \033[36mbuild\033[0m   Build the container image"
	@echo "  \033[36mrun\033[0m     Build and run interactively"
	@echo "  \033[36mclean\033[0m   Remove the container image"
	@echo "  \033[36mtest\033[0m    Run with example data"
	@echo "  \033[36mtest-unit\033[0m Run unit tests"
	@echo "  \033[36mnuke\033[0m    Reset the container builder"
	@echo "  \033[36mhelp\033[0m    Show this message"
	@echo ""
	@echo "\033[90mFiles in $(HOST_DIR) are mounted at /mnt/shared\033[0m"
	@echo ""
