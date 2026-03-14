#!/bin/bash
set -euo pipefail

source .env

SCRIPT="${1:-hook_netflix_android.js}"

uv run python run.py --android "$SCRIPT"
