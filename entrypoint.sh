#!/bin/bash

cd /app
python3 secret.py > .env

set -a
. .env
set +a

python3 main.py