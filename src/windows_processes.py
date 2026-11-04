"""List HTS processes without requesting memory-read rights or elevating the viewer."""
import ctypes
from ctypes import wintypes as w
from types import SimpleNamespace

PC_TARGETS = {'provestkrun.exe', 'provestk.exe'}


class ProcessEntry(ctypes.Structure):
    _fields_ = [('size', w.DWORD), ('usage', w.DWORD), ('pid', w.DWORD),
                ('heap', ctypes.c_size_t), ('module', w.DWORD), ('threads', w.DWORD),
                ('parent', w.DWORD), ('priority', w.LONG), ('flags', w.DWORD),
                ('name', w.WCHAR * 260)]


def pc_processes():
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.CreateToolhelp32Snapshot.argtypes = [w.DWORD, w.DWORD]
    kernel.CreateToolhelp32Snapshot.restype = w.HANDLE
    kernel.Process32FirstW.argtypes = kernel.Process32NextW.argtypes = [w.HANDLE, ctypes.POINTER(ProcessEntry)]
    kernel.CloseHandle.argtypes = [w.HANDLE]
    snapshot = kernel.CreateToolhelp32Snapshot(2, 0)
    if snapshot == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        entry = ProcessEntry(); entry.size = ctypes.sizeof(entry)
        ok = kernel.Process32FirstW(snapshot, ctypes.byref(entry))
        if not ok:
            error = ctypes.get_last_error()
            if error != 18:  # ERROR_NO_MORE_FILES
                raise ctypes.WinError(error)
        result = []
        while ok:
            if entry.name.lower() in PC_TARGETS:
                result.append(SimpleNamespace(pid=entry.pid, name=entry.name))
            ok = kernel.Process32NextW(snapshot, ctypes.byref(entry))
        error = ctypes.get_last_error()
        if error != 18:
            raise ctypes.WinError(error)
        return result
    finally:
        kernel.CloseHandle(snapshot)


def elevated(pid=None):
    """Return True/False for TokenElevation, or None if querying was denied."""
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    security = ctypes.WinDLL('advapi32', use_last_error=True)
    kernel.OpenProcess.argtypes = [w.DWORD, w.BOOL, w.DWORD]
    kernel.OpenProcess.restype = kernel.GetCurrentProcess.restype = w.HANDLE
    kernel.CloseHandle.argtypes = [w.HANDLE]
    security.OpenProcessToken.argtypes = [w.HANDLE, w.DWORD, ctypes.POINTER(w.HANDLE)]
    security.GetTokenInformation.argtypes = [w.HANDLE, ctypes.c_int, ctypes.c_void_p, w.DWORD, ctypes.POINTER(w.DWORD)]
    process = kernel.GetCurrentProcess() if pid is None else kernel.OpenProcess(0x1000, False, pid)
    if not process:
        return None
    token = w.HANDLE()
    try:
        if not security.OpenProcessToken(process, 8, ctypes.byref(token)):
            return None
        value, length = w.DWORD(), w.DWORD()
        if not security.GetTokenInformation(token, 20, ctypes.byref(value), ctypes.sizeof(value), ctypes.byref(length)):
            return None
        return bool(value.value)
    finally:
        if token: kernel.CloseHandle(token)
        if pid is not None: kernel.CloseHandle(process)


def needs_elevation(pid):
    return elevated() is False and elevated(pid) is True
