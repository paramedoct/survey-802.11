#!/usr/bin/env bash
set -euo pipefail

sudo apt update
sudo apt install \
  iproute2 \
  iw \
  make \
  python3 \
  python3-setuptools \
  python3-venv
