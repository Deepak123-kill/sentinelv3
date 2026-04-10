@echo off
wsl -d Ubuntu -e bash -c "python3 \"$(wslpath -a '%~dp0cli_app/sentinel.py')\" %*"
