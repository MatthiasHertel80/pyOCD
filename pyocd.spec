# -*- mode: python ; coding: utf-8 -*-

import os
import sys
import platform
from PyInstaller.utils.hooks import collect_dynamic_libs
import libusb_package
from pathlib import Path

# Get environment variables with python site packages location (needs to be set before pyinstaller run)
SITE_PACKAGES = os.getenv('SITE_PACKAGES', '')
lib_suffix = '.so' #'.pyd' if sys.platform == 'win32' else '.so'
CMSIS_PATH = str(Path(SITE_PACKAGES) / 'cmsis_pack_manager' / 'cmsis_pack_manager' / f'native{lib_suffix}')
LIBUSB_PATH = collect_dynamic_libs('libusb_package', destdir='.')

print(LIBUSB_PATH)

a = Analysis(
    ['pyocd.py'],
    pathex=[],
    binaries=[
        (CMSIS_PATH, 'cmsis_pack_manager/cmsis_pack_manager'),  # Explicit CMSIS library path
        *collect_dynamic_libs('cmsis_pack_manager'),
        *collect_dynamic_libs('libusb_package')
    ],
    datas=[
        ('pyocd/debug/sequences/sequences.lark', 'pyocd/debug/sequences'),
        ('pyocd/debug/svd/svd_data.zip', 'pyocd/debug/svd')
    ],
    hiddenimports=[
        'capstone',
        'cmsis_pack_manager',
        'colorama',
        'importlib_metadata',
        'importlib_resources',
        'importlib_resources.trees',  # Add explicit import  
        'intelhex',
        'intervaltree',
        'lark',
        'libusb',
        'libusb_package',
        'natsort',
        'prettytable',
        'pyelftools',
        'pylink_square',
        'pyusb',
        'yaml',  # for pyyaml
        'six',
        'typing_extensions'
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure, a.zipped_data)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='pyocd',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='pyocd'
)