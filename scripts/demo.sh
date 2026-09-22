#!/bin/sh
set -eu
export PYTHONPATH="${PYTHONPATH:-}:src"
python3 -m hetzner_security.cli.main audit \
  --input benchmarks/scenarios/v0.1-insecure.json \
  --format json --output examples/reports/demo.json \
  --coverage-ledger examples/reports/coverage-ledger.json
python3 -m hetzner_security.cli.main audit \
  --input benchmarks/scenarios/v0.1-insecure.json \
  --format markdown --output examples/reports/demo.md
python3 -m hetzner_security.cli.main audit \
  --input benchmarks/scenarios/v0.1-insecure.json \
  --format sarif --output examples/reports/demo.sarif
