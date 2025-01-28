# -*- mode: python ; coding: utf-8 -*-

import os
import sys
import platform
from pathlib import Path

# Get environment variables with python site packages location (needs to be set before pyinstaller run)
SITE_PACKAGES = os.getenv('SITE_PACKAGES', '')
lib_suffix = '.so' #'.pyd' if sys.platform == 'win32' else '.so'
CMSIS_PATH = str(Path(SITE_PACKAGES) / 'cmsis_pack_manager' / 'cmsis_pack_manager' / f'native{lib_suffix}')

# Platform specific libusb paths
def get_libusb_path(site_packages):
    machine = platform.machine()
    if sys.platform == 'darwin':
        arch = 'x64' if machine in ('x86_64', 'AMD64') else 'arm64'
        # Use newer macOS version if available
        lib_path = Path(site_packages) / 'libusb/_platform/_macos/x64/11.6/libusb-1.0.0.dylib'
        if not lib_path.exists():
            lib_path = Path(site_packages) / 'libusb/_platform/_macos/x64/10.7/libusb-1.0.0.dylib'
    elif sys.platform == 'linux':
        arch = 'x64' if machine == 'x86_64' else 'aarch64'
        lib_path = Path(site_packages) / f'libusb/_platform/_linux/{arch}/libusb-1.0.so'
    elif sys.platform == 'win32':
        arch = 'x64' if machine == 'AMD64' else 'x86'
        lib_path = Path(site_packages) / f'libusb/_platform/_windows/{arch}/libusb-1.0.dll'
    
    if not lib_path.exists():
        raise RuntimeError(f"libusb not found at {lib_path}")
    return str(lib_path)

LIBUSB_PATH = get_libusb_path(SITE_PACKAGES)

a = Analysis(
    ['pyocd.py'],
    pathex=[],
    binaries=[
        (CMSIS_PATH, 'cmsis_pack_manager/cmsis_pack_manager'),
        (LIBUSB_PATH, '.')
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