#!/bin/sh

git config --global --unset commit.template
git config --global --add safe.directory /home/vscode/app
git config --global fetch.prune true
git config --global --add --bool push.autoSetupRemote true
git config --global commit.gpgSign false
git config --global user.signingkey $(gpg --list-secret-keys --with-colons | grep -B 3 "uid.*$(git config user.name)" | cut -d: -f5 | sed ':a;N;$!ba;s/\n//g')
git branch --merged|egrep -v '\*|develop|main|master'|xargs git branch -d

direnv allow /home/vscode/app/.envrc
