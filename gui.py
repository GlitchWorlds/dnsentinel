import tkinter as tk
import os
import sys
import threading
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from agent import load_config, load_blocklist, save_blocklist, serve
CFG = load_config()
SRV_THREAD = None
def refresh_block(box, search=None):
    box.delete(0, 'end')
    s = (search or '').strip().lower()
    alld = sorted(load_blocklist(CFG))
    for d in alld:
        if (not s) or (s in d):
            box.insert('end', d)
def add_block(entry, box, status):
    d = entry.get().strip().lower().rstrip('.')
    if not d:
        return
    s = load_blocklist(CFG)
    s.add(d)
    save_blocklist(CFG, s)
    entry.delete(0, 'end')
    refresh_block(box)
    status.config(text='blocked: ' + d)
def remove_block(box, status):
    sel = box.curselection()
    if not sel:
        return
    d = box.get(sel[0])
    s = load_blocklist(CFG)
    s.discard(d)
    save_blocklist(CFG, s)
    refresh_block(box)
    status.config(text='unblocked: ' + d)
def tail_file(path, n=200):
    try:
        fh = open(path, encoding='utf-8')
        lines = fh.read().splitlines()
        fh.close()
        if len(lines) > n:
            lines = lines[len(lines)-n:]
        return lines
    except OSError:
        return ['(empty)']
def start_server(status):
    global SRV_THREAD
    alive = SRV_THREAD and SRV_THREAD.is_alive()
    if alive:
        status.config(text='already running')
        return
    SRV_THREAD = threading.Thread(target=serve, args=(CFG,), daemon=True)
    SRV_THREAD.start()
    status.config(text='serving')
def stop_server(status):
    status.config(text='stop: restart app')
def refresh_logs(root, dns_text, egress_text):
    base = os.path.dirname(os.path.abspath(__file__))
    dpath = os.path.join(base, 'logs', 'dns.log')
    epath = os.path.join(base, 'logs', 'egress.log')
    pairs = ((dns_text, dpath), (egress_text, epath))
    for widget, path in pairs:
        widget.config(state='normal')
        widget.delete('1.0', 'end')
        for line in tail_file(path, 200):
            widget.insert('end', line + chr(10))
        widget.config(state='disabled')
    root.after(2000, lambda: refresh_logs(root, dns_text, egress_text))
def clear_views(dns_text, egress_text):
    dns_text.config(state='normal')
    dns_text.delete('1.0', 'end')
    dns_text.config(state='disabled')
    egress_text.config(state='normal')
    egress_text.delete('1.0', 'end')
    egress_text.config(state='disabled')
def open_logs(status):
    base = os.path.dirname(os.path.abspath(__file__))
    ldir = os.path.join(base, 'logs')
    try:
        os.startfile(ldir)
        status.config(text='logs opened')
    except OSError:
        status.config(text='logs dir')
def main():
    root = tk.Tk()
    root.title('DNSentinel')
    root.geometry('640x560')
    info = CFG.get('listen', '127.0.0.1') + ':' + str(CFG.get('port', 53))
    top = tk.Frame(root)
    top.pack(fill='x', padx=8, pady=2)
    tk.Label(top, text=info, anchor='w').pack(fill='x')
    tk.Label(top, text='admin for port 53', anchor='w').pack(fill='x')
    srow = tk.Frame(root)
    srow.pack(pady=2)
    status = tk.Label(root, text='ready exact-domain', anchor='w')
    tk.Button(srow, text='Start', command=lambda: start_server(status)).pack(side='left', padx=4)
    tk.Button(srow, text='Stop', command=lambda: stop_server(status)).pack(side='left', padx=4)
    box = tk.Listbox(root, height=8)
    box.pack(fill='both', expand=True, padx=8)
    entry = tk.Entry(root)
    entry.pack(fill='x', padx=8)
    search = tk.Entry(root)
    search.pack(fill='x', padx=8)
    brow = tk.Frame(root)
    brow.pack(pady=2)
    tk.Button(brow, text='Add', command=lambda: add_block(entry, box, status)).pack(side='left', padx=4)
    tk.Button(brow, text='Remove', command=lambda: remove_block(box, status)).pack(side='left', padx=4)
    tk.Button(brow, text='Refresh', command=lambda: refresh_block(box, search.get())).pack(side='left', padx=4)
    search.bind('KeyRelease', lambda e: refresh_block(box, search.get()))
    dns_text = tk.Text(root, height=8, state='disabled')
    dns_text.pack(fill='both', expand=True, padx=8)
    egress_text = tk.Text(root, height=8, state='disabled')
    egress_text.pack(fill='both', expand=True, padx=8)
    lrow = tk.Frame(root)
    lrow.pack(pady=2)
    tk.Button(lrow, text='Clear', command=lambda: clear_views(dns_text, egress_text)).pack(side='left', padx=4)
    tk.Button(lrow, text='Logs', command=lambda: open_logs(status)).pack(side='left', padx=4)
    status.pack(fill='x', padx=8)
    refresh_block(box)
    refresh_logs(root, dns_text, egress_text)
    root.mainloop()
if '__name__' == '__main__':
    main()
