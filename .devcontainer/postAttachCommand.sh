#!/bin/sh

git config --global --unset commit.template
git config --global --add safe.directory /home/vscode/app
git config --global fetch.prune true
git config --global --add --bool push.autoSetupRemote true
git config --global commit.gpgSign false
git config --global user.signingkey $(gpg --list-secret-keys --with-colons | grep -B 3 "uid.*$(git config user.name)" | cut -d: -f5 | sed ':a;N;$!ba;s/\n//g')
git branch --merged|egrep -v '\*|develop|main|master'|xargs git branch -d

# .zshrc にシェル初期化を追加 (venv activate, .env 読み込み, alias)
if ! grep -q '# >>> app shell init >>>' ~/.zshrc 2>/dev/null; then
  cat >> ~/.zshrc << 'SHELL_INIT'

# >>> app shell init >>>
source /home/vscode/app/.venv/bin/activate
set -a; source /home/vscode/app/.env 2>/dev/null; set +a
export GIT_AUTHOR_NAME="${GIT_AUTHOR_NAME:-$(git config user.name)}"
export GIT_AUTHOR_EMAIL="${GIT_AUTHOR_EMAIL:-$(git config user.email)}"
export GIT_COMMITTER_NAME="${GIT_COMMITTER_NAME:-$(git config user.name)}"
export GIT_COMMITTER_EMAIL="${GIT_COMMITTER_EMAIL:-$(git config user.email)}"
alias frida-trace="frida-trace -H \$ANDROID_HOST --ui-port \$UI_PORT"
alias frida-ps="frida-ps -H \$ANDROID_HOST"
# <<< app shell init <<<
SHELL_INIT
fi

# ── Background log collectors ──
cd /home/vscode/app

# mitmproxy: Netflix iOS capture (port 9080)
nohup uv run mitmdump \
  --listen-port 9080 \
  --set block_global=false \
  --ssl-insecure \
  -s packages/mitmproxy/netflix_ios_capture.py \
  > /tmp/mitmproxy.log 2>&1 &

# oslog: Tweak ログ収集 (SSH 接続できない場合は自動終了)
nohup bash .vscode/scripts/oslog_stream.sh \
  > /tmp/oslog_stream.log 2>&1 &
