#!/usr/bin/env python3
import os
import signal
import subprocess
import webbrowser
from pathlib import Path
import tkinter as tk
from tkinter import messagebox

# ========= CONFIGURE THESE =========

# Absolute paths to each app's directory
AI_IDS_DIR = Path("/home/khoanguyen/AI-IDS/AI-IDS")
CHIRON_DIR = Path("/home/khoanguyen/Chiron/Chiron/web")

# Commands to start each app
AI_IDS_CMD = ["make", "dev"]            # starts Flask API + Vite dev server
CHIRON_CMD = ["npm", "run", "preview"]  # starts Vite preview

# URLs of each UI
AI_IDS_URL = "http://localhost:5173"
CHIRON_URL = "http://localhost:4173"

# ========= INTERNAL STATE =========

ai_ids_proc: subprocess.Popen | None = None
chiron_proc: subprocess.Popen | None = None


def _start_server(name: str, cwd: Path, command: list[str], proc_name: str):
    """
    Start a dev server in its own process group (so we can kill it cleanly later).
    Does NOT open the browser.
    """
    global ai_ids_proc, chiron_proc

    if not cwd.exists():
        messagebox.showerror("Error", f"{name} directory does not exist:\n{cwd}")
        return

    proc = ai_ids_proc if proc_name == "ai" else chiron_proc

    # Start process if not already running
    if proc is None or proc.poll() is not None:
        try:
            new_proc = subprocess.Popen(
                command,
                cwd=str(cwd),
                preexec_fn=os.setsid,  # Linux/Unix: start new process group
            )
            if proc_name == "ai":
                ai_ids_proc = new_proc
            else:
                chiron_proc = new_proc
        except FileNotFoundError as e:
            messagebox.showerror(
                "Error",
                f"Failed to start {name}.\n"
                f"Command: {' '.join(command)}\n"
                f"Error: {e}\n\n"
                "Make sure the tools (make/npm) are installed and the package.json/Makefile exist.",
            )
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start {name}:\n{e}")


def start_all_servers():
    """Start AI-IDS and Chiron dev servers when the launcher opens."""
    _start_server("AI-IDS", AI_IDS_DIR, AI_IDS_CMD, "ai")
    _start_server("Chiron", CHIRON_DIR, CHIRON_CMD, "chiron")


def open_ai_ids():
    """Just open the AI-IDS UI (server is started on launcher startup)."""
    webbrowser.open(AI_IDS_URL)


def open_chiron():
    """Just open the Chiron UI (server is started on launcher startup)."""
    webbrowser.open(CHIRON_URL)


def _kill_proc_group(proc: subprocess.Popen | None):
    """Kill the whole process group for a dev server, if it's running."""
    if proc is None:
        return
    if proc.poll() is not None:  # already exited
        return
    try:
        pgid = os.getpgid(proc.pid)
        os.killpg(pgid, signal.SIGTERM)
    except Exception:
        # Fall back to terminating just the parent if group-kill fails
        try:
            proc.terminate()
        except Exception:
            pass


def on_close(root: tk.Tk):
    """Terminate dev servers when the launcher closes."""
    global ai_ids_proc, chiron_proc

    if messagebox.askokcancel("Quit", "Close launcher and stop dev servers?"):
        _kill_proc_group(ai_ids_proc)
        _kill_proc_group(chiron_proc)
        root.destroy()


def main():
    root = tk.Tk()
    root.title("Capstone Launcher")
    root.geometry("300x180")

    title = tk.Label(root, text="Choose Application", font=("Helvetica", 14))
    title.pack(pady=10)

    btn_ai = tk.Button(root, text="Open AI-IDS", width=20, command=open_ai_ids)
    btn_ai.pack(pady=5)

    btn_chiron = tk.Button(root, text="Open Chiron", width=20, command=open_chiron)
    btn_chiron.pack(pady=5)

    info = tk.Label(
        root,
        text="Dev servers start when this window opens.\nButtons only open the UIs.",
        justify="center",
        font=("Helvetica", 9),
    )
    info.pack(pady=10)

    # Start both dev servers *as soon as* the launcher is open
    start_all_servers()

    root.protocol("WM_DELETE_WINDOW", lambda: on_close(root))
    root.mainloop()


if __name__ == "__main__":
    main()

