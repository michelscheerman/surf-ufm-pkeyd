# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec file for SURF UFM PKey Daemon (single file)

a = Analysis(
    ['surf_ufm_pkeyd.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=[
        'yaml',
        'requests',
        'urllib3',
        'urllib3.util.retry',
        'requests.adapters',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'tkinter',
        'matplotlib',
        'numpy',
        'PIL',
        'PyQt5',
        'PyQt6',
        'PySide2',
        'PySide6',
    ],
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='surf_ufm_pkeyd',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)