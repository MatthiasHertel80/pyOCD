# -*- mode: python ; coding: utf-8 -*-

import os
import sys
from pathlib import Path

# Get environment variables with defaults
SITE_PACKAGES = os.getenv('SITE_PACKAGES', '')
lib_suffix = '.so' #'.pyd' if sys.platform == 'win32' else '.so'
CMSIS_PATH = str(Path(SITE_PACKAGES) / 'cmsis_pack_manager' / 'cmsis_pack_manager' / f'native{lib_suffix}')

a = Analysis(
    ['pyocd.py'],
    pathex=[],
    binaries=[
        (CMSIS_PATH, 'cmsis_pack_manager/cmsis_pack_manager')
    ],
    datas=[
        ('pyocd/debug/sequences/sequences.lark', 'pyocd/debug/sequences'),
        ('pyocd/debug/svd/svd_data.zip', 'pyocd/debug/svd')
    ],
    hiddenimports=['cmsis_pack_manager'],
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