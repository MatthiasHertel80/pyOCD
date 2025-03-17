#!/bin/bash

pip3 install .
python3 get_site-packages.py

rm -R build
rm -R dist

#export value returned from get_site-packages.py
export $(python3 get_site-packages.py)

pyinstaller pyocd.spec --log-level=ERROR --clean

./dist/pyocd/pyocd list --version