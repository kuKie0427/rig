# -*- mode: python ; coding: utf-8 -*-
import os
import sys
from pathlib import Path

# Add the current directory to the path (should be project root)
project_root = Path.cwd()
sys.path.insert(0, str(project_root))

# Define data files to include
datas = [
    # Include server static files
    (str(project_root / 'rig/server/static'), 'rig/server/static'),
    # Include the logo if needed
    (str(project_root / 'media/logo.png'), 'media'),
]

# Hidden imports - modules that PyInstaller might miss
hiddenimports = [
    # Built-in modules that PyInstaller sometimes misses
    '_struct',
    'struct',
    '_socket',
    '_ssl',
    '_hashlib',
    '_json',
    # rig modules
    'rig.server.cli',
    'rig.server.api_v2',
    'rig.server.workspace_api',
    'rig.tools',
    'rig.tools.shell',
    'rig.tools.python',
    'rig.tools.patch',
    'rig.tools.save',
    'rig.tools.read',
    'rig.tools.browser',
    'rig.tools.vision',
    'rig.tools.screenshot',
    'rig.tools.computer',
    'rig.tools.gh',
    'rig.tools.tmux',
    'rig.tools.chats',
    'rig.tools.rag',
    'rig.tools.subagent',
    'rig.llm.llm_openai',
    'rig.llm.llm_anthropic',
    'rig.llm.models',
    'rig.mcp.client',
    # Flask and dependencies
    'flask',
    'flask_cors',
    'werkzeug',
    'jinja2',
    'markupsafe',
    'itsdangerous',
    'click',
    'blinker',
    'importlib_metadata',
    'platformdirs',
    # tiktoken
    'tiktoken_ext.openai_public',
    'tiktoken_ext',
]

# Exclude modules that might cause issues or aren't needed
excludes = [
    'matplotlib',
    'tkinter',
    'IPython.kernel',
    'jupyter',
    'notebook',
    'pytest',
    'sphinx',
    'scipy',  # TTS functionality not needed for server
    'sounddevice',  # TTS functionality not needed for server
    'numpy',  # TTS functionality not needed for server
]

a = Analysis(
    [str(project_root / 'rig/server/__main__.py')],
    pathex=[],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=excludes,
    noarchive=False,
    optimize=0,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='rig-server',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
