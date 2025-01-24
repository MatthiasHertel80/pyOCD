# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['pyocd.py'],
    pathex=[],
    binaries=[
      ('/Library/Frameworks/Python.framework/Versions/3.13/lib/python3.13/site-packages/cmsis_pack_manager/cmsis_pack_manager/native.so', 'cmsis_pack_manager')
    ],
    datas=[
        ('pyocd/debug/sequences/sequences.lark', 'pyocd/debug/sequences'),
        ('pyocd/debug/svd/svd_data.zip', 'pyocd/debug/svd')
    ],
    hiddenimports=[],
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
    a.binaries,
    a.zipfiles,
    a.datas,
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
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='pyocd',
)
