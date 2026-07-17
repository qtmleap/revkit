#!/bin/zsh
set -e

USER_NAME="$(whoami)"
USER_HOME="/home/${USER_NAME}"

sudo mkdir -p \
  "${USER_HOME}/app/.venv" \
  "${USER_HOME}/.cache/uv" \
  "${USER_HOME}/.cache/pip" \
  "${USER_HOME}/.bun/install/cache" \
  "${USER_HOME}/.npm"

sudo chown -R "${USER_NAME}":"${USER_NAME}" \
  "${USER_HOME}/app/.venv" \
  "${USER_HOME}/.cache/uv" \
  "${USER_HOME}/.cache/pip" \
  "${USER_HOME}/.bun/install/cache" \
  "${USER_HOME}/.npm"

# Silence direnv output.
# See https://github.com/direnv/direnv/issues/1418
mkdir -p ~/.config/direnv
cat > ~/.config/direnv/direnv.toml <<'EOF'
[global]
log_format = ""
hide_env_diff = true
EOF

# Sync deps if the project defines them.
if [ -f pyproject.toml ]; then
  if [ -f uv.lock ]; then
    uv sync --frozen
  else
    uv sync
  fi
fi
if [ -f package.json ]; then
  if [ -f bun.lock ]; then
    bun install --frozen-lockfile --ignore-scripts
  else
    bun install --ignore-scripts
  fi
fi
