# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_data_files
from PyInstaller.utils.hooks import copy_metadata

datas = [('C:\\final year project\\mini siem\\mini_siem\\app.py', 'app.py'), ('C:\\final year project\\mini siem\\mini_siem\\dashboard.py', 'dashboard.py'), ('C:\\final year project\\mini siem\\mini_siem\\collector.py', 'collector.py'), ('C:\\final year project\\mini siem\\mini_siem\\database.py', 'database.py'), ('C:\\final year project\\mini siem\\mini_siem\\detection_engine.py', 'detection_engine.py'), ('C:\\final year project\\mini siem\\mini_siem\\ai_analyzer.py', 'ai_analyzer.py'), ('C:\\final year project\\mini siem\\mini_siem\\models', 'models'), ('C:\\final year project\\mini siem\\mini_siem\\rules', 'rules')]
datas += collect_data_files('streamlit')
datas += collect_data_files('plotly')
datas += copy_metadata('streamlit')
datas += copy_metadata('plotly')
datas += copy_metadata('pandas')


a = Analysis(
    ['C:\\final year project\\mini siem\\mini_siem\\mini_siem_launcher.py'],
    pathex=[],
    binaries=[],
    datas=datas,
    hiddenimports=['win32timezone'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['cv2', 'google', 'grpc', 'langchain', 'langcodes', 'matplotlib', 'scipy', 'sklearn', 'spacy', 'tensorflow', 'thinc', 'torch', 'transformers'],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='MiniSIEM',
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
    name='MiniSIEM',
)
