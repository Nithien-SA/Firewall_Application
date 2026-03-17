# Git Push Steps

## First Time Setup (only do this once)

git init
git remote add origin https://github.com/Nithien-SA/Firewall_Application.git
git branch -M main

## Every Time You Want to Push
git add .
git commit -m "Update"
git push -u origin main

## After the first push, you can just use `git push` instead of `git push -u origin main`.

git add . ; git commit -m "update" ; git push

## Useful Extra Commands

| Command | What it does |
|---|---|
| `git status` | See what files changed |
| `git log --oneline` | See past commits |
| `git remote -v` | Check your remote URL |
