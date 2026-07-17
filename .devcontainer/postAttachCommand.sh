#!/bin/zsh

git config --global --unset commit.template 2>/dev/null || true
git config --global --add safe.directory /home/vscode/app
git config --global fetch.prune true
git config --global --add --bool push.autoSetupRemote true
git config --global commit.gpgSign false
git branch --merged | egrep -v '\*|develop|main|master' | xargs -r git branch -d
[ -f .envrc ] && direnv allow || true
