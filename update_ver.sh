#!/bin/bash
echo "[*] Starting ..."
if [ $# -ne 2 ]; then
    echo "[!] 2 arguments required; old_version, new_version"
    echo "[*] Quitting."
    exit
fi
echo "[+] Updating version ..."
sed -i "s/${1}/${2}/g" VERSION
sed -i "s/${1}/${2}/g" setup.py
sed -i "s/${1}/${2}/g" PatrowlEnginesUtils/__init__.py

echo "[+] Adding to version control ..."
git add VERSION PatrowlEnginesUtils/__init__.py setup.py
git commit -m "Updated VERSION (${2})"

echo "[+] Updated to ${2}."
echo "[*] Done."
