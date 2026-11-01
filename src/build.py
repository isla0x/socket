"""Build into a separate directory; never collect over the source directory."""
from pathlib import Path
import shutil
import subprocess
import sys

import PySide6
import pefile

root = Path(__file__).resolve().parent
destination = root.parent / 'build-output'
subprocess.run([
    sys.executable, '-m', 'PyInstaller', '--noconfirm', '--windowed', '--onedir',
    '--name', 'SocketInspector', '--hidden-import', 'encodings.cp949',
    '--hidden-import', '_codecs_kr', '--hidden-import', '_multibytecodec',
    '--add-data', str(root / 'agent.js') + ';.',
    '--add-data', str(root / 'agent-shinyoung.js') + ';.',
    '--add-data', str(root / 'compat-prelude.js') + ';.',
    '--distpath', str(destination), '--workpath', str(root.parent / '.build' / 'cache'),
    '--specpath', str(root.parent / '.build'), str(root / 'app.py'),
], check=True)
qt = Path(PySide6.__file__).parent
internal = destination / 'SocketInspector' / '_internal'
for name in ('VCRUNTIME140.dll', 'VCRUNTIME140_1.dll'):
    candidate = qt / name
    if candidate.exists():
        shutil.copy2(candidate, internal / name)
# Qt uses the unversioned Windows ICU API. An unrelated ICU on PATH can be
# collected by PyInstaller with the same DLL name but incompatible _78 exports.
icu = internal / 'icuuc.dll'
if icu.exists():
    pe = pefile.PE(str(icu))
    exports = {symbol.name for symbol in pe.DIRECTORY_ENTRY_EXPORT.symbols}
    pe.close()
    if b'ucnv_open' not in exports:
        icu.unlink()  # Fall back to Windows' own compatible ICU; do not modify Windows.
print('Built:', destination / 'SocketInspector' / 'SocketInspector.exe')
