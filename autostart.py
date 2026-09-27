import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from agent import load_config, BASE_DIR
try:
    import winreg
except Exception:
    winreg = None
APP = 'DNSentinel'
RUN_KEY = 'Software\\Microsoft\\Windows\\CurrentVersion\\Run'
def target():
    py = sys.executable
    if py.lower().endswith('python.exe'):
        py = py[:-10] + 'pythonw.exe'
    ag = os.path.join(BASE_DIR, 'agent.py')
    return '"%s" "%s" serve' % (py, ag)
def enable():
    if winreg is None:
        print('AUTOSTART no-winreg')
        return 2
    k = winreg.CreateKey(winreg.HKEY_CURRENT_USER, RUN_KEY)
    winreg.SetValueEx(k, APP, 0, winreg.REG_SZ, target())
    winreg.CloseKey(k)
    print('AUTOSTART enabled ' + target())
    return 0
def disable():
    if winreg is None:
        print('AUTOSTART no-winreg')
        return 2
    try:
        k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE)
        winreg.DeleteValue(k, APP)
        winreg.CloseKey(k)
    except FileNotFoundError:
        pass
    print('AUTOSTART disabled')
    return 0
def status():
    if winreg is None:
        print('AUTOSTART no-winreg')
        return 2
    try:
        k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_READ)
        v, _ = winreg.QueryValueEx(k, APP)
        winreg.CloseKey(k)
        print('AUTOSTART enabled ' + v)
        return 0
    except FileNotFoundError:
        print('AUTOSTART disabled')
        return 1
def roundtrip():
    cfg = load_config()
    print('CONFIG ok listen=' + str(cfg.get('listen')) + ' port=' + str(cfg.get('port')))
    return 0
def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if not argv or argv[0] == 'status':
        roundtrip()
        return status()
    if argv[0] == 'enable':
        return enable()
    if argv[0] == 'disable':
        return disable()
    if argv[0] == 'check':
        return roundtrip()
    print('usage: autostart.py [status|enable|disable|check]')
    return 2
if __name__ == '__main__':
    sys.exit(main())
