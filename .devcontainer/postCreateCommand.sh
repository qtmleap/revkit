#!/bin/sh

sudo chown -R "$(whoami)":"$(whoami)" /home/"$(whoami)"/app/.venv
uv sync
