import importlib
import secrets
import subprocess
import sys
import threading
import tkinter as tk
import webbrowser
from pathlib import Path
from tkinter import messagebox, scrolledtext, ttk

APP_DIR = Path(__file__).resolve().parent
WORDS_FILE = APP_DIR / "data" / "words.txt"
USED_PASSPHRASES_FILE = APP_DIR / "data" / "used_passphrases.txt"
REQUIREMENTS_FILE = APP_DIR / "requirements.txt"

SEPARATORS = {
    "Hyphen (-)": "-",
    "Space": " ",
    "Underscore (_)": "_",
    "None": "",
}


def install_dependencies() -> tuple[bool, str]:
    command = [sys.executable, "-m", "pip", "install", "-r", str(REQUIREMENTS_FILE)]
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=300,
            cwd=APP_DIR,
        )
    except Exception as exc:
        return False, str(exc)

    if completed.returncode != 0:
        output = (completed.stderr or completed.stdout or "pip install failed").strip()
        return False, output
    return True, ""


def load_blockchain_modules() -> tuple[bool, str, dict]:
    try:
        import requests  # noqa: F401

        if "blockchain" in sys.modules:
            blockchain_module = importlib.reload(sys.modules["blockchain"])
        else:
            blockchain_module = importlib.import_module("blockchain")

        return True, "", {
            "MAJOR_CHAINS": blockchain_module.MAJOR_CHAINS,
            "BlockchainResult": blockchain_module.BlockchainResult,
            "check_passphrase_all_chains": blockchain_module.check_passphrase_all_chains,
            "find_balance_on_any_chain": blockchain_module.find_balance_on_any_chain,
            "format_result": blockchain_module.format_result,
            "format_results_summary": blockchain_module.format_results_summary,
        }
    except Exception as exc:
        return False, str(exc), {}


def bootstrap_blockchain(auto_install: bool = True) -> tuple[bool, str, dict]:
    ready, error, modules = load_blockchain_modules()
    if ready:
        return True, "", modules

    if not auto_install:
        return False, error, {}

    installed, install_error = install_dependencies()
    if not installed:
        combined = error
        if install_error:
            combined = f"{error}\n\nAuto-install failed:\n{install_error}"
        return False, combined, {}

    return load_blockchain_modules()


BLOCKCHAIN_READY, BLOCKCHAIN_ERROR, _BOOT_MODULES = bootstrap_blockchain(auto_install=True)
MAJOR_CHAINS = _BOOT_MODULES.get("MAJOR_CHAINS", [])
BlockchainResult = _BOOT_MODULES.get("BlockchainResult")
check_passphrase_all_chains = _BOOT_MODULES.get("check_passphrase_all_chains")
find_balance_on_any_chain = _BOOT_MODULES.get("find_balance_on_any_chain")
format_result = _BOOT_MODULES.get("format_result")
format_results_summary = _BOOT_MODULES.get("format_results_summary")


def load_words() -> list[str]:
    if not WORDS_FILE.exists():
        raise FileNotFoundError(f"Word list not found: {WORDS_FILE}")

    words = []
    seen = set()
    for line in WORDS_FILE.read_text(encoding="utf-8").splitlines():
        word = line.strip().lower()
        if word and word not in seen:
            seen.add(word)
            words.append(word)

    if len(words) < 2:
        raise ValueError("Word list must contain at least 2 unique words.")

    return words


def load_used_passphrases() -> set[str]:
    if not USED_PASSPHRASES_FILE.exists():
        return set()

    used = set()
    for line in USED_PASSPHRASES_FILE.read_text(encoding="utf-8").splitlines():
        text = line.strip()
        if text:
            used.add(text)
    return used


def save_used_passphrase(passphrase: str) -> None:
    USED_PASSPHRASES_FILE.parent.mkdir(parents=True, exist_ok=True)
    with USED_PASSPHRASES_FILE.open("a", encoding="utf-8") as handle:
        handle.write(passphrase + "\n")


class PassphraseApp:
    def __init__(self, root: tk.Tk, words: list[str]) -> None:
        self.root = root
        self.words = words
        self.used_passphrases = load_used_passphrases()
        self.used_lock = threading.Lock()
        self.last_blockchain_results = []
        self.last_hit = None
        self.check_in_progress = False
        self.auto_hunt_active = False
        self.auto_hunt_thread: threading.Thread | None = None
        self.checked_count = 0
        self.blockchain_ready = BLOCKCHAIN_READY
        self.blockchain_error = BLOCKCHAIN_ERROR
        self.major_chains = list(MAJOR_CHAINS)
        self.install_in_progress = False

        root.title("Word Combiner")
        root.geometry("640x780")
        root.minsize(600, 720)
        root.configure(padx=16, pady=16)

        title = ttk.Label(root, text="Auto Wallet Hunter", font=("Segoe UI", 16, "bold"))
        title.pack(anchor="w")

        subtitle = ttk.Label(
            root,
            text=(
                "Click once to start. The app generates unique passphrases, checks all major "
                "blockchains for a balance, and keeps going until it finds one or you stop it."
            ),
            wraplength=600,
        )
        subtitle.pack(anchor="w", pady=(4, 12))

        buttons = ttk.Frame(root)
        buttons.pack(fill="x", pady=(0, 16))

        self.auto_hunt_button = ttk.Button(
            buttons,
            text="Start Auto Hunt",
            command=self.start_auto_hunt,
        )
        self.auto_hunt_button.pack(side="left")

        self.stop_button = ttk.Button(
            buttons,
            text="Stop",
            command=self.stop_auto_hunt,
            state="disabled",
        )
        self.stop_button.pack(side="left", padx=(8, 0))

        self.install_button = ttk.Button(
            buttons,
            text="Install Dependencies",
            command=self.install_and_retry,
        )
        self.install_button.pack(side="left", padx=(8, 0))

        options = ttk.LabelFrame(root, text="Passphrase options", padding=12)
        options.pack(fill="x")

        max_words = min(12, len(words))
        default_count = min(4, max_words)

        ttk.Label(options, text="Number of words").grid(row=0, column=0, sticky="w")
        self.word_count = tk.IntVar(value=default_count)
        ttk.Spinbox(
            options,
            from_=2,
            to=max_words,
            textvariable=self.word_count,
            width=6,
        ).grid(row=0, column=1, sticky="w", padx=(8, 0))

        ttk.Label(options, text="Separator").grid(row=1, column=0, sticky="w", pady=(10, 0))
        self.separator = tk.StringVar(value="Hyphen (-)")
        ttk.Combobox(
            options,
            textvariable=self.separator,
            values=list(SEPARATORS.keys()),
            state="readonly",
            width=18,
        ).grid(row=1, column=1, sticky="w", padx=(8, 0), pady=(10, 0))

        self.capitalize = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            options,
            text="Capitalize each word",
            variable=self.capitalize,
        ).grid(row=2, column=0, columnspan=2, sticky="w", pady=(10, 0))

        blockchain_options = ttk.LabelFrame(root, text="Blockchain coverage", padding=12)
        blockchain_options.pack(fill="x", pady=(12, 0))

        self.chains_label = ttk.Label(
            blockchain_options,
            text=self._chains_label_text(),
            wraplength=580,
        )
        self.chains_label.grid(row=0, column=0, sticky="w")

        ttk.Label(
            blockchain_options,
            text="Uses SHA-256(passphrase) to derive wallet addresses, then queries public explorers.",
            wraplength=580,
            foreground="#666666",
        ).grid(row=1, column=0, sticky="w", pady=(8, 0))

        self.blockchain_hint = ttk.Label(
            blockchain_options,
            text=self._blockchain_hint_text(),
            wraplength=580,
            foreground="#884400" if not self.blockchain_ready else "#666666",
        )
        self.blockchain_hint.grid(row=2, column=0, sticky="w", pady=(8, 0))

        output = ttk.LabelFrame(root, text="Current passphrase", padding=12)
        output.pack(fill="x", pady=(16, 0))

        self.result = tk.StringVar(value="Click Start Auto Hunt to begin")
        ttk.Label(
            output,
            textvariable=self.result,
            font=("Consolas", 13),
            wraplength=580,
            anchor="w",
            justify="left",
        ).pack(fill="x")

        self.progress_status = tk.StringVar(value="Idle")
        ttk.Label(
            root,
            textvariable=self.progress_status,
            foreground="#444444",
        ).pack(anchor="w", pady=(8, 0))

        chain_output = ttk.LabelFrame(root, text="Blockchain results", padding=12)
        chain_output.pack(fill="both", expand=True, pady=(12, 0))

        self.blockchain_status = scrolledtext.ScrolledText(
            chain_output,
            height=12,
            font=("Consolas", 9),
            wrap="word",
            state="disabled",
        )
        self.blockchain_status.pack(fill="both", expand=True)

        secondary_buttons = ttk.Frame(root)
        secondary_buttons.pack(fill="x", pady=(12, 0))

        ttk.Button(secondary_buttons, text="Copy passphrase", command=self.copy).pack(side="left")
        self.explorer_button = ttk.Button(
            secondary_buttons,
            text="Open explorer",
            command=self.open_explorer,
            state="disabled",
        )
        self.explorer_button.pack(side="left", padx=(8, 0))

        self.refresh_ui_state()

        status = ttk.Label(
            root,
            text=(
                f"{len(words)} words loaded | "
                f"{len(self.used_passphrases)} passphrases already used (never repeated)"
            ),
            foreground="#666666",
        )
        status.pack(anchor="w", pady=(12, 0))

    def _chains_label_text(self) -> str:
        if self.blockchain_ready and self.major_chains:
            return f"Networks checked each round: {', '.join(self.major_chains)}"
        return "Networks checked each round: unavailable until dependencies are installed"

    def _blockchain_hint_text(self) -> str:
        if self.blockchain_ready:
            return "Blockchain checking is ready. You need internet access."
        return (
            "Start Auto Hunt is disabled because required Python packages are missing.\n"
            f"Error: {self.blockchain_error}\n"
            "Click 'Install Dependencies', or run: python -m pip install -r requirements.txt"
        )

    def refresh_ui_state(self) -> None:
        self.chains_label.configure(text=self._chains_label_text())
        self.blockchain_hint.configure(
            text=self._blockchain_hint_text(),
            foreground="#884400" if not self.blockchain_ready else "#666666",
        )
        if self.blockchain_ready:
            self.auto_hunt_button.configure(state="disabled" if self.auto_hunt_active else "normal")
            self.install_button.configure(state="disabled")
        else:
            self.auto_hunt_button.configure(state="disabled")
            self.install_button.configure(
                state="disabled" if self.install_in_progress else "normal",
            )

    def _apply_blockchain_modules(self, modules: dict) -> None:
        global check_passphrase_all_chains, find_balance_on_any_chain, format_result, format_results_summary

        self.major_chains = list(modules["MAJOR_CHAINS"])
        self.blockchain_ready = True
        self.blockchain_error = ""
        check_passphrase_all_chains = modules["check_passphrase_all_chains"]
        find_balance_on_any_chain = modules["find_balance_on_any_chain"]
        format_result = modules["format_result"]
        format_results_summary = modules["format_results_summary"]
        self.refresh_ui_state()

    def install_and_retry(self) -> None:
        if self.install_in_progress:
            return

        self.install_in_progress = True
        self.progress_status.set("Installing dependencies... this may take a minute.")
        self.install_button.configure(state="disabled")
        self.set_blockchain_text("Installing Python packages from requirements.txt...")

        thread = threading.Thread(target=self._install_worker, daemon=True)
        thread.start()

    def _install_worker(self) -> None:
        installed, install_error = install_dependencies()
        if not installed:
            self.root.after(
                0,
                self._finish_install,
                False,
                f"Install failed:\n{install_error}",
            )
            return

        ready, error, modules = load_blockchain_modules()
        if ready:
            self.root.after(0, self._finish_install, True, "")
            self.root.after(0, self._apply_blockchain_modules, modules)
            return

        self.root.after(0, self._finish_install, False, f"Imports still failing:\n{error}")

    def _finish_install(self, success: bool, message: str) -> None:
        self.install_in_progress = False
        if success:
            self.progress_status.set("Dependencies installed. You can now click Start Auto Hunt.")
            self.set_blockchain_text("Dependencies installed successfully. Click Start Auto Hunt.")
            messagebox.showinfo(
                "Ready",
                "Dependencies installed successfully. Click Start Auto Hunt to begin.",
            )
        else:
            self.blockchain_error = message
            self.progress_status.set("Dependency install failed.")
            self.set_blockchain_text(message)
            self.refresh_ui_state()
            messagebox.showerror("Install failed", message)

    def get_word_count(self) -> int:
        try:
            count = int(self.word_count.get())
        except (ValueError, tk.TclError):
            count = 4
        return max(2, min(count, len(self.words)))

    def pick_unique_words(self, count: int) -> list[str]:
        pool = self.words.copy()
        picked = []
        for _ in range(count):
            index = secrets.randbelow(len(pool))
            picked.append(pool.pop(index))
        return picked

    def build_passphrase(self) -> str:
        count = self.get_word_count()
        picked = self.pick_unique_words(count)
        if self.capitalize.get():
            picked = [word.capitalize() for word in picked]

        separator = SEPARATORS[self.separator.get()]
        passphrase = separator.join(picked)

        # REMOVED: No more random numbers at the end
        return passphrase

    def reserve_unique_passphrase(self) -> str | None:
        for _ in range(5000):
            candidate = self.build_passphrase()
            with self.used_lock:
                if candidate not in self.used_passphrases:
                    self.used_passphrases.add(candidate)
                    save_used_passphrase(candidate)
                    return candidate
        return None

    def current_passphrase(self) -> str | None:
        text = self.result.get().strip()
        if not text or text.startswith("Click"):
            return None
        return text

    def set_blockchain_text(self, text: str) -> None:
        self.blockchain_status.configure(state="normal")
        self.blockchain_status.delete("1.0", tk.END)
        self.blockchain_status.insert(tk.END, text)
        self.blockchain_status.configure(state="disabled")

    def set_hunt_buttons(self, running: bool) -> None:
        self.auto_hunt_active = running
        if self.blockchain_ready:
            self.auto_hunt_button.configure(state="disabled" if running else "normal")
        else:
            self.auto_hunt_button.configure(state="disabled")
        self.stop_button.configure(state="normal" if running else "disabled")

    def start_auto_hunt(self) -> None:
        if not self.blockchain_ready:
            messagebox.showerror(
                "Blockchain unavailable",
                (
                    "Required packages are not installed yet.\n\n"
                    "Click 'Install Dependencies' in the app, or run:\n"
                    "python -m pip install -r requirements.txt"
                ),
            )
            return
        if self.auto_hunt_active:
            return

        count = self.get_word_count()
        if count > len(self.words):
            messagebox.showerror(
                "Invalid setting",
                f"You only have {len(self.words)} unique words. Lower the word count.",
            )
            return

        self.checked_count = 0
        self.last_hit = None
        self.last_blockchain_results = []
        self.explorer_button.configure(state="disabled")
        self.set_hunt_buttons(True)
        self.progress_status.set("Auto hunt started. Generating and checking passphrases...")
        self.set_blockchain_text("Waiting for first passphrase...")

        self.auto_hunt_thread = threading.Thread(target=self._auto_hunt_worker, daemon=True)
        self.auto_hunt_thread.start()

    def stop_auto_hunt(self) -> None:
        self.auto_hunt_active = False
        self.progress_status.set("Stopping after the current check finishes...")

    def _auto_hunt_worker(self) -> None:
        while self.auto_hunt_active:
            passphrase = self.reserve_unique_passphrase()
            if passphrase is None:
                self.root.after(
                    0,
                    self._finish_auto_hunt,
                    "Could not create a new unique passphrase. Try different options.",
                )
                return

            self.checked_count += 1
            current_count = self.checked_count
            self.root.after(0, self._update_current_passphrase, passphrase, current_count)

            try:
                # OPTIMIZED FOR 10/SECOND
                results = check_passphrase_all_chains(
                    passphrase,
                    early_exit=True,
                    balance_only=True,
                    timeout=0.3,
                    max_workers=64,
                )
                hit = find_balance_on_any_chain(results)
            except Exception as exc:
                message = f"Round {current_count} failed:\n{exc}"
                self.root.after(0, self._update_round_status, passphrase, current_count, message, [])
                continue

            summary = format_results_summary(results)
            self.root.after(
                0,
                self._update_round_status,
                passphrase,
                current_count,
                summary,
                results,
            )

            if hit is not None:
                self.root.after(0, self._on_balance_found, passphrase, hit, results)
                return

        self.root.after(0, self._finish_auto_hunt, "Auto hunt stopped.")

    def _update_current_passphrase(self, passphrase: str, count: int) -> None:
        self.result.set(passphrase)
        self.progress_status.set(f"Checked: {count - 1} | Checking passphrase #{count} on all networks...")

    def _update_round_status(
        self,
        passphrase: str,
        count: int,
        summary: str,
        results: list[BlockchainResult],
    ) -> None:
        self.result.set(passphrase)
        self.last_blockchain_results = results
        self.progress_status.set(f"Checked: {count} | No balance yet. Continuing...")
        self.set_blockchain_text(f"Passphrase #{count}: {passphrase}\n\n{summary}")

    def _on_balance_found(
        self,
        passphrase: str,
        hit: BlockchainResult,
        results: list[BlockchainResult],
    ) -> None:
        self.auto_hunt_active = False
        self.last_hit = hit
        self.last_blockchain_results = results
        self.result.set(passphrase)
        self.progress_status.set(
            f"FOUND after {self.checked_count} passphrases on {hit.chain}."
        )
        self.set_blockchain_text(
            "BALANCE FOUND\n"
            f"Passphrase: {passphrase}\n\n"
            f"{format_result(hit)}\n\n"
            f"All networks:\n{format_results_summary(results)}"
        )
        self.set_hunt_buttons(False)
        self.explorer_button.configure(state="normal")
        messagebox.showinfo(
            "Balance found",
            (
                f"Found a wallet with balance on {hit.chain}.\n\n"
                f"Passphrase: {passphrase}\n"
                f"Address: {hit.address}\n"
                f"Balance: {hit.balance}"
            ),
        )

    def _finish_auto_hunt(self, message: str) -> None:
        self.set_hunt_buttons(False)
        if not self.last_hit:
            self.progress_status.set(message)

    def copy(self) -> None:
        text = self.current_passphrase()
        if not text:
            messagebox.showinfo("Nothing to copy", "Start the auto hunt first.")
            return

        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.root.update()
        messagebox.showinfo("Copied", "Passphrase copied to clipboard.")

    def open_explorer(self) -> None:
        target = self.last_hit
        if target is None:
            for result in self.last_blockchain_results:
                if result.explorer_url:
                    target = result
                    break
        if target is None or not target.explorer_url:
            messagebox.showinfo("No explorer link", "No explorer link is available yet.")
            return
        webbrowser.open(target.explorer_url)


def main() -> None:
    try:
        words = load_words()
    except (FileNotFoundError, ValueError) as exc:
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror("Startup error", str(exc))
        sys.exit(1)

    root = tk.Tk()
    PassphraseApp(root, words)
    root.mainloop()


if __name__ == "__main__":
    main()
