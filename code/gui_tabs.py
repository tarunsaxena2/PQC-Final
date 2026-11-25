"""
gui_tabs.py - Keygen, Hide and Extract tabs on the MOCK facade.

Run on its own:   python code\\gui_tabs.py
Later, build_tabs(parent) is dropped into the main window next to the
existing Benchmark tab. Integration day: change only the facade import.

The run_* functions hold the logic and return (ok, message), so they can be
tested without opening a window:   python code\\gui_tabs.py --selftest
"""
import sys
from pathlib import Path

import facade_mock as facade  # swap for the real facade on integration day


# ---------------------------------------------------------------- logic
def _need(value, what):
    if not str(value).strip():
        return "Please choose the %s." % what
    return None


def run_keygen(level, out_dir):
    msg = _need(out_dir, "folder for the key files")
    if msg:
        return False, msg
    try:
        ek, dk = facade.keygen(int(level), out_dir)
    except facade.FacadeError as err:
        return False, str(err)
    except OSError as err:
        return False, "Could not write the key files: %s" % err
    return True, "Keys created.\nPublic key (give to sender): %s\nPrivate key (keep secret): %s" % (ek, dk)


def run_hide(carrier, file, ek, level, mode, qkd_key_file, out):
    for value, what in ((carrier, "carrier audio file"), (file, "file to hide"),
                        (ek, "receiver's public key")):
        msg = _need(value, what)
        if msg:
            return False, msg
    try:
        path = facade.hide(carrier, file, ek, int(level), mode,
                           qkd_key_file=(qkd_key_file.strip() or None),
                           out=(out.strip() or None))
    except facade.PayloadTooLargeError as err:
        return False, "The file is too big for this carrier. %s" % err
    except facade.FacadeError as err:
        return False, str(err)
    except OSError as err:
        return False, "File problem: %s" % err
    return True, "Done. Stego file written to:\n%s" % path


def run_extract(stego, dk, qkd_key_file, out):
    for value, what in ((stego, "stego file"), (dk, "private key file")):
        msg = _need(value, what)
        if msg:
            return False, msg
    try:
        path = facade.extract(stego, dk, qkd_key_file=(qkd_key_file.strip() or None),
                              out=(out.strip() or None))
    except facade.KeyMismatchError:
        return False, "Wrong key: this private key does not open this stego file. Nothing was extracted."
    except facade.FacadeError as err:
        return False, str(err)
    except OSError as err:
        return False, "File problem: %s" % err
    return True, "Done. Hidden file written to:\n%s" % path


# ---------------------------------------------------------------- UI
def build_tabs(parent):
    import tkinter as tk
    from tkinter import ttk, filedialog

    nb = ttk.Notebook(parent)

    def make_tab(title):
        f = ttk.Frame(nb, padding=10)
        nb.add(f, text=title)
        return f

    def field(frame, label, var, r, browse=None, save=False):
        ttk.Label(frame, text=label).grid(row=r, column=0, sticky="w", pady=3)
        e = ttk.Entry(frame, textvariable=var, width=52)
        e.grid(row=r, column=1, pady=3, padx=4)
        if browse == "file":
            def pick():
                p = (filedialog.asksaveasfilename() if save else filedialog.askopenfilename())
                if p:
                    var.set(p)
            ttk.Button(frame, text="...", width=3, command=pick).grid(row=r, column=2)
        elif browse == "dir":
            def pick_dir():
                p = filedialog.askdirectory()
                if p:
                    var.set(p)
            ttk.Button(frame, text="...", width=3, command=pick_dir).grid(row=r, column=2)
        return e

    def status_box(frame, r):
        lbl = ttk.Label(frame, text="", wraplength=620, justify="left")
        lbl.grid(row=r, column=0, columnspan=3, sticky="w", pady=10)
        return lbl

    def show(lbl, result):
        ok, message = result
        lbl.config(text=message, foreground=("#1a7f37" if ok else "#c62828"))

    # ---- Keygen
    t = make_tab("Keygen")
    level = tk.StringVar(value="768")
    kdir = tk.StringVar(value=str(Path("keys").resolve()))
    ttk.Label(t, text="Security level").grid(row=0, column=0, sticky="w", pady=3)
    ttk.Combobox(t, textvariable=level, values=[str(x) for x in facade.LEVELS],
                 state="readonly", width=8).grid(row=0, column=1, sticky="w", padx=4)
    field(t, "Save keys in folder", kdir, 1, browse="dir")
    k_status = status_box(t, 3)
    ttk.Button(t, text="Generate keys",
               command=lambda: show(k_status, run_keygen(level.get(), kdir.get()))
               ).grid(row=2, column=0, sticky="w", pady=6)

    # ---- Hide
    t = make_tab("Hide")
    carrier, hfile, hek = tk.StringVar(), tk.StringVar(), tk.StringVar()
    hlevel, hmode = tk.StringVar(value="768"), tk.StringVar(value="pqc")
    hqkd, hout = tk.StringVar(), tk.StringVar()
    field(t, "Carrier audio", carrier, 0, browse="file")
    field(t, "File to hide", hfile, 1, browse="file")
    field(t, "Receiver public key (ek)", hek, 2, browse="file")
    ttk.Label(t, text="Security level").grid(row=3, column=0, sticky="w", pady=3)
    ttk.Combobox(t, textvariable=hlevel, values=[str(x) for x in facade.LEVELS],
                 state="readonly", width=8).grid(row=3, column=1, sticky="w", padx=4)
    ttk.Label(t, text="Mode").grid(row=4, column=0, sticky="w", pady=3)
    ttk.Combobox(t, textvariable=hmode, values=sorted(facade.MODES),
                 state="readonly", width=18).grid(row=4, column=1, sticky="w", padx=4)
    qkd_entry = field(t, "QKD key file (simulation)", hqkd, 5, browse="file")
    field(t, "Output file (optional)", hout, 6, browse="file", save=True)
    h_status = status_box(t, 8)

    def sync_qkd(*_):
        qkd_entry.config(state=("normal" if hmode.get() == "hybrid-qkdsim" else "disabled"))
    hmode.trace_add("write", sync_qkd)
    sync_qkd()
    ttk.Button(t, text="Hide file",
               command=lambda: show(h_status, run_hide(carrier.get(), hfile.get(), hek.get(),
                                                       hlevel.get(), hmode.get(), hqkd.get(),
                                                       hout.get()))
               ).grid(row=7, column=0, sticky="w", pady=6)

    # ---- Extract
    t = make_tab("Extract")
    stego, edk, eqkd, eout = tk.StringVar(), tk.StringVar(), tk.StringVar(), tk.StringVar()
    field(t, "Stego file", stego, 0, browse="file")
    field(t, "Private key (dk)", edk, 1, browse="file")
    field(t, "QKD key file (hybrid-qkdsim only)", eqkd, 2, browse="file")
    field(t, "Output file (optional)", eout, 3, browse="file", save=True)
    e_status = status_box(t, 5)
    ttk.Button(t, text="Extract file",
               command=lambda: show(e_status, run_extract(stego.get(), edk.get(),
                                                          eqkd.get(), eout.get()))
               ).grid(row=4, column=0, sticky="w", pady=6)
    return nb


def _selftest():
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        carrier = td / "c.wav"
        carrier.write_bytes(b"RIFFfake")
        msg = td / "m.txt"
        msg.write_bytes(b"gui test")
        qkd = td / "q.key"
        qkd.write_bytes(b"simulation")
        ok, _ = run_keygen("768", td / "k")
        assert ok
        ek, dk = td / "k" / "ek_768.bin", td / "k" / "dk_768.bin"
        ok, _ = run_keygen("768", td / "k2")
        dk_other = td / "k2" / "dk_768.bin"

        ok, m = run_hide("", msg, ek, "768", "pqc", "", "")
        assert not ok and "carrier" in m
        ok, _ = run_hide(carrier, msg, ek, "768", "pqc", "", str(td / "s.bin"))
        assert ok
        ok, m = run_extract(td / "s.bin", dk_other, "", "")
        assert not ok and "Wrong key" in m
        ok, _ = run_extract(td / "s.bin", dk, "", str(td / "out.txt"))
        assert ok and (td / "out.txt").read_bytes() == b"gui test"
        ok, m = run_hide(carrier, msg, ek, "768", "hybrid-qkdsim", "", "")
        assert not ok and "simulated-QKD" in m
        ok, _ = run_hide(carrier, msg, ek, "768", "hybrid-qkdsim", str(qkd), str(td / "s2.bin"))
        assert ok
        big = td / "big.bin"
        big.write_bytes(b"x" * (facade.MOCK_CAPACITY + 1))
        ok, m = run_hide(carrier, big, ek, "768", "pqc", "", "")
        assert not ok and "too big" in m
    print("gui_tabs selftest: PASS")


def main():
    if "--selftest" in sys.argv:
        _selftest()
        return
    import tkinter as tk
    root = tk.Tk()
    root.title("PQC Stego tool - Keygen / Hide / Extract (MOCK facade)")
    root.geometry("760x420")
    build_tabs(root).pack(fill="both", expand=True)
    root.mainloop()


if __name__ == "__main__":
    main()
