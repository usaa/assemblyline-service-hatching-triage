#!/usr/bin/env bash

set -e

echo "running postCreateCommand.."

sudo apt update && sudo apt upgrade -y
sudo apt-get install -yy libffi8 libfuzzy2 libmagic1 build-essential libffi-dev libfuzzy-dev

pip3 install -r requirements-unittest.txt
pip3 install -r requirements.txt