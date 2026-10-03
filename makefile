SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c
.ONESHELL:
.DEFAULT_GOAL := all

ROOT_DIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
DESTDIR ?=
export DESTDIR

.PHONY: all clean setup backup

all:
	@if [ "$$(id -u)" -ne 0 ]; then
	  exec sudo -- make --no-print-directory -C "$(ROOT_DIR)" DESTDIR="$(DESTDIR)" all
	fi
	case "$$DESTDIR" in
	  ''|/*) ;;
	  *) echo "DESTDIR must be empty or absolute" >&2; exit 1 ;;
	esac
	for tool in python3 iw ip systemctl install; do
	  if ! command -v "$$tool" >/dev/null 2>&1; then
	    echo "$$tool is required; run ./3rdparty/setup-debian.sh" >&2
	    exit 1
	  fi
	done
	if ! python3 -c 'import sys; raise SystemExit(sys.version_info < (3, 13))'; then
	  echo "Python 3.13 or newer is required" >&2
	  exit 1
	fi
	if ! python3 -c 'import ensurepip, setuptools'; then
	  echo "python3-venv and python3-setuptools are required" >&2
	  exit 1
	fi
	was_active=false
	if systemctl is-active --quiet survey-802.11.service; then
	  was_active=true
	  systemctl stop survey-802.11.service
	fi
	install -d -m 0755 "$(DESTDIR)/opt/survey-802.11" \
	  "$(DESTDIR)/etc/survey-802.11" "$(DESTDIR)/etc/systemd/system" \
	  "$(DESTDIR)/usr/local/bin"
	python3 -m venv --system-site-packages "$(DESTDIR)/opt/survey-802.11/venv"
	"$(DESTDIR)/opt/survey-802.11/venv/bin/pip" install \
	  --disable-pip-version-check --no-build-isolation --no-deps --no-index \
	  "$(ROOT_DIR)"
	ln -sfn "$(DESTDIR)/opt/survey-802.11/venv/bin/survey-802.11" \
	  "$(DESTDIR)/usr/local/bin/survey-802.11"
	if [ ! -e "$(DESTDIR)/etc/survey-802.11/survey-802.11.toml" ]; then
	  install -m 0644 "$(ROOT_DIR)/config/survey-802.11.example.toml" \
	    "$(DESTDIR)/etc/survey-802.11/survey-802.11.toml"
	fi
	install -m 0644 "$(ROOT_DIR)/systemd/survey-802.11.service" \
	  "$(DESTDIR)/etc/systemd/system/survey-802.11.service"
	systemctl daemon-reload
	if [ "$$was_active" = true ]; then
	  systemctl start survey-802.11.service
	fi
	echo "installed; edit /etc/survey-802.11/survey-802.11.toml and run: survey-802.11 enable"

clean:
	@if [ "$$(id -u)" -ne 0 ]; then
	  exec sudo -- make --no-print-directory -C "$(ROOT_DIR)" DESTDIR="$(DESTDIR)" clean
	fi
	case "$$DESTDIR" in
	  ''|/*) ;;
	  *) echo "DESTDIR must be empty or absolute" >&2; exit 1 ;;
	esac
	if [ -e "$(DESTDIR)/etc/systemd/system/survey-802.11.service" ]; then
	  systemctl disable --now survey-802.11.service
	fi
	rm -f "$(DESTDIR)/etc/systemd/system/survey-802.11.service" \
	  "$(DESTDIR)/usr/local/bin/survey-802.11"
	rm -rf "$(DESTDIR)/opt/survey-802.11"
	systemctl daemon-reload
	echo "removed application; /etc/survey-802.11 and /var/lib/survey-802.11 were preserved"

setup:
	@"$(ROOT_DIR)/3rdparty/setup-debian.sh"

backup:
	@if [ "$$(id -u)" -ne 0 ]; then
	  exec sudo -- /opt/survey-802.11/venv/bin/survey-802.11 backup
	fi
	exec /opt/survey-802.11/venv/bin/survey-802.11 backup
