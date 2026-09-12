from __future__ import annotations

import queue
import tkinter as tk
from tkinter import filedialog, messagebox

import customtkinter as ctk

from client.worker import BackgroundWorker

QUEUE_MS = 100
DEFAULT_SERVER = "http://127.0.0.1:8000"


class VaxChatApp(ctk.CTk):
    def __init__(self) -> None:
        super().__init__()
        self.title("vaxchat")
        self.geometry("980x640")
        self.minsize(820, 520)

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self._out: queue.Queue = queue.Queue()
        self.worker = BackgroundWorker(self._out)
        self.username: str | None = None
        self.contacts: list[dict] = []
        self.selected_username: str | None = None
        self.messages_by_peer: dict[str, list[dict]] = {}
        self.unlocked = False
        self._busy = False
        self._queue_job: str | None = None
        self._server_url = DEFAULT_SERVER

        self.container = ctk.CTkFrame(self, fg_color="transparent")
        self.container.pack(fill="both", expand=True)
        self._show_login()
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self._drain_queue()

    def _clear_container(self) -> None:
        for child in self.container.winfo_children():
            child.destroy()

    def _set_status(self, text: str) -> None:
        if hasattr(self, "status_var"):
            self.status_var.set(text)

    def _drain_queue(self) -> None:
        try:
            while True:
                kind, payload = self._out.get_nowait()
                self._handle_event(kind, payload)
        except queue.Empty:
            pass
        self._queue_job = self.after(QUEUE_MS, self._drain_queue)

    def _handle_event(self, kind: str, payload: dict) -> None:
        if kind == "auth_ok":
            self._busy = False
            self.username = payload.get("username")
            self._show_main()
        elif kind == "logged_out":
            self.username = None
            self.contacts = []
            self.selected_username = None
            self.messages_by_peer = {}
            self.unlocked = False
            self._show_login()
        elif kind == "contacts":
            self.contacts = payload.get("contacts") or []
            self._redraw_contacts()
        elif kind == "messages":
            self.messages_by_peer = payload.get("messages_by_peer") or {}
            self.unlocked = bool(payload.get("unlocked"))
            if self.selected_username:
                self._render_chat()
        elif kind == "status":
            self._set_status(payload.get("text") or "")
        elif kind == "error":
            self._busy = False
            msg = payload.get("message") or "Error"
            if hasattr(self, "login_status") and self.login_status.winfo_exists():
                self.login_status.configure(text=msg)
            self._set_status(msg)
        elif kind == "send_done":
            self._busy = False
            if not payload.get("ok"):
                self._set_status(payload.get("error") or "Send failed")
        elif kind == "key_loaded":
            fp = payload.get("fingerprint") or ""
            short = fp[-8:] if fp else "?"
            if hasattr(self, "key_var"):
                self.key_var.set(f"Private key loaded · {short}")
            self.unlocked = True
            self._render_chat()
        elif kind == "key_generated":
            self._on_key_generated(payload)
        elif kind == "contact_added":
            self._set_status("Contact added.")
        elif kind == "contact_removed":
            if self.selected_username == payload.get("username"):
                self.selected_username = None
                if hasattr(self, "chat_title"):
                    self.chat_title.configure(text="Select a contact")
                self._render_chat()

    def _show_login(self) -> None:
        self._clear_container()
        frame = ctk.CTkFrame(self.container)
        frame.place(relx=0.5, rely=0.5, anchor="center")

        ctk.CTkLabel(frame, text="vaxchat", font=ctk.CTkFont(size=28, weight="bold")).pack(padx=40, pady=(28, 4))
        ctk.CTkLabel(
            frame,
            text="Encrypted messages. The server only stores ciphertext.",
            text_color="gray70",
        ).pack(pady=(0, 16))

        self.server_entry = ctk.CTkEntry(frame, width=320, placeholder_text="Server URL")
        self.server_entry.insert(0, self._server_url)
        self.server_entry.pack(padx=40, pady=6)

        self.user_entry = ctk.CTkEntry(frame, width=320, placeholder_text="Username")
        self.user_entry.pack(padx=40, pady=6)

        self.pass_entry = ctk.CTkEntry(frame, width=320, placeholder_text="Password", show="•")
        self.pass_entry.pack(padx=40, pady=6)

        btns = ctk.CTkFrame(frame, fg_color="transparent")
        btns.pack(pady=12)
        ctk.CTkButton(btns, text="Log in", width=140, command=lambda: self._auth(False)).pack(side="left", padx=6)
        ctk.CTkButton(btns, text="Register", width=140, fg_color="#1f8a4c", command=lambda: self._auth(True)).pack(
            side="left", padx=6
        )

        self.login_status = ctk.CTkLabel(frame, text="", text_color="gray70")
        self.login_status.pack(padx=40, pady=(4, 24))
        self.pass_entry.bind("<Return>", lambda _e: self._auth(False))

    def _auth(self, register: bool) -> None:
        if self._busy:
            return
        username = self.user_entry.get().strip()
        password = self.pass_entry.get()
        server = self.server_entry.get().strip() or DEFAULT_SERVER
        if not username or not password:
            self.login_status.configure(text="Username and password required.")
            return
        self._server_url = server.rstrip("/")
        self.login_status.configure(text="Working…")
        self._busy = True
        kind = "register" if register else "login"
        self.worker.submit(kind, username=username, password=password, server=self._server_url)

    def _show_main(self) -> None:
        self._clear_container()
        root = ctk.CTkFrame(self.container, fg_color="transparent")
        root.pack(fill="both", expand=True, padx=12, pady=12)
        root.grid_columnconfigure(1, weight=1)
        root.grid_rowconfigure(1, weight=1)

        top = ctk.CTkFrame(root)
        top.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 8))
        self.key_var = tk.StringVar(value="Private key: not loaded")
        ctk.CTkLabel(top, text=f"Signed in as {self.username}", font=ctk.CTkFont(weight="bold")).pack(
            side="left", padx=12, pady=10
        )
        ctk.CTkLabel(top, textvariable=self.key_var, text_color="gray70").pack(side="left", padx=8)
        ctk.CTkButton(top, text="Log out", width=80, fg_color="gray30", command=self._logout).pack(
            side="right", padx=10, pady=8
        )
        ctk.CTkButton(top, text="Generate keys", width=120, command=self._generate_keys).pack(side="right", padx=4)
        ctk.CTkButton(top, text="Load private key", width=140, command=self._load_key_dialog).pack(side="right", padx=4)

        left = ctk.CTkFrame(root, width=240)
        left.grid(row=1, column=0, sticky="nsw", padx=(0, 8))
        left.grid_propagate(False)
        ctk.CTkLabel(left, text="Contacts", font=ctk.CTkFont(weight="bold")).pack(anchor="w", padx=12, pady=(12, 6))
        btnrow = ctk.CTkFrame(left, fg_color="transparent")
        btnrow.pack(fill="x", padx=8, pady=(0, 8))
        ctk.CTkButton(btnrow, text="Add", width=70, command=self._add_contact_dialog).pack(side="left", padx=2)
        ctk.CTkButton(btnrow, text="Remove", width=80, fg_color="gray30", command=self._remove_contact).pack(
            side="left", padx=2
        )
        self.contact_list = ctk.CTkScrollableFrame(left, width=220)
        self.contact_list.pack(fill="both", expand=True, padx=8, pady=(0, 12))

        right = ctk.CTkFrame(root)
        right.grid(row=1, column=1, sticky="nsew")
        right.grid_rowconfigure(1, weight=1)
        right.grid_columnconfigure(0, weight=1)
        self.chat_title = ctk.CTkLabel(right, text="Select a contact", font=ctk.CTkFont(size=16, weight="bold"))
        self.chat_title.grid(row=0, column=0, sticky="w", padx=14, pady=(12, 4))
        self.history = ctk.CTkTextbox(right, wrap="word", state="disabled")
        self.history.grid(row=1, column=0, sticky="nsew", padx=12, pady=6)

        compose = ctk.CTkFrame(right, fg_color="transparent")
        compose.grid(row=2, column=0, sticky="ew", padx=12, pady=(4, 12))
        compose.grid_columnconfigure(0, weight=1)
        self.compose = ctk.CTkEntry(compose, placeholder_text="Type a message (encrypted on this machine)")
        self.compose.grid(row=0, column=0, sticky="ew", padx=(0, 8))
        self.compose.bind("<Return>", lambda _e: self._send())
        ctk.CTkButton(compose, text="Send", width=90, command=self._send).grid(row=0, column=1)

        self.status_var = tk.StringVar(value="Ready")
        ctk.CTkLabel(root, textvariable=self.status_var, text_color="gray60", anchor="w").grid(
            row=2, column=0, columnspan=2, sticky="ew", pady=(6, 0)
        )

        self._redraw_contacts()
        self.worker.submit("refresh_contacts")

    def _logout(self) -> None:
        self.worker.submit("logout")

    def _on_close(self) -> None:
        if self._queue_job is not None:
            try:
                self.after_cancel(self._queue_job)
            except Exception:
                pass
            self._queue_job = None
        self.worker.shutdown()
        self.destroy()

    def _redraw_contacts(self) -> None:
        if not hasattr(self, "contact_list"):
            return
        for child in self.contact_list.winfo_children():
            child.destroy()
        for contact in self.contacts:
            name = contact["username"]
            btn = ctk.CTkButton(
                self.contact_list,
                text=name,
                fg_color="transparent",
                anchor="w",
                command=lambda n=name: self._select_contact(n),
            )
            btn.pack(fill="x", pady=2)

    def _select_contact(self, username: str) -> None:
        self.selected_username = username
        self.chat_title.configure(text=username)
        self._render_chat()

    def _render_chat(self) -> None:
        if not hasattr(self, "history"):
            return
        self.history.configure(state="normal")
        self.history.delete("1.0", "end")
        if not self.selected_username:
            self.history.configure(state="disabled")
            return
        if not self.unlocked:
            self.history.insert("end", "Load your private key to decrypt this conversation.\n")
            # Still show any placeholder lines if present.
        rows = self.messages_by_peer.get(self.selected_username, [])
        if not rows and self.unlocked:
            self.history.insert("end", "No messages yet.\n")
        for row in rows:
            who = row.get("who") or "?"
            mark = row.get("mark") or ""
            text = row.get("text") or ""
            self.history.insert("end", f"{who}{mark}: {text}\n")
        self.history.see("end")
        self.history.configure(state="disabled")

    def _send(self) -> None:
        if self._busy:
            return
        peer = self.selected_username
        text = self.compose.get().strip()
        if not peer:
            self._set_status("Select a contact first.")
            return
        if not text:
            return
        if not self.unlocked:
            self._set_status("Load your private key before sending.")
            return
        self.compose.delete(0, "end")
        self._busy = True
        self._set_status("Encrypting…")
        self.worker.submit("send", peer=peer, text=text)

    def _load_key_dialog(self) -> None:
        dialog = ctk.CTkToplevel(self)
        dialog.title("Load private key")
        dialog.geometry("520x420")
        dialog.transient(self)
        dialog.grab_set()
        ctk.CTkLabel(dialog, text="Paste an ASCII-armored private key, or open a file.").pack(padx=16, pady=(16, 8))
        box = ctk.CTkTextbox(dialog, height=220)
        box.pack(fill="both", expand=True, padx=16, pady=8)
        phrase = ctk.CTkEntry(dialog, placeholder_text="Passphrase (if the key is protected)", show="•")
        phrase.pack(fill="x", padx=16, pady=6)

        def from_file() -> None:
            path = filedialog.askopenfilename(
                parent=dialog,
                title="Private key file",
                filetypes=[("ASCII armor", "*.asc *.key *.txt"), ("All files", "*.*")],
            )
            if not path:
                return
            with open(path, encoding="utf-8") as handle:
                box.delete("1.0", "end")
                box.insert("1.0", handle.read())

        def accept() -> None:
            armor = box.get("1.0", "end").strip()
            if not armor:
                messagebox.showerror("Key", "Paste or open a private key first.", parent=dialog)
                return
            self._set_status("Loading key…")
            self.worker.submit("load_key", armor=armor, passphrase=phrase.get())
            dialog.destroy()

        row = ctk.CTkFrame(dialog, fg_color="transparent")
        row.pack(pady=12)
        ctk.CTkButton(row, text="Open file…", command=from_file).pack(side="left", padx=6)
        ctk.CTkButton(row, text="Unlock", command=accept).pack(side="left", padx=6)

    def _generate_keys(self) -> None:
        dialog = ctk.CTkToplevel(self)
        dialog.title("Generate keypair")
        dialog.geometry("420x240")
        dialog.transient(self)
        dialog.grab_set()
        ctk.CTkLabel(dialog, text="An Ed25519/Cv25519 key will be created on this machine.").pack(
            padx=16, pady=(16, 8)
        )
        name = ctk.CTkEntry(dialog, placeholder_text="Name on the key")
        name.insert(0, self.username or "vaxchat")
        name.pack(fill="x", padx=16, pady=6)
        phrase = ctk.CTkEntry(dialog, placeholder_text="Optional passphrase", show="•")
        phrase.pack(fill="x", padx=16, pady=6)
        status = ctk.CTkLabel(dialog, text="")
        status.pack(pady=4)
        self._gen_dialog = dialog
        self._gen_status = status

        def go() -> None:
            status.configure(text="Generating… this can take a few seconds.")
            self.worker.submit(
                "generate_key",
                name=name.get().strip() or "vaxchat",
                passphrase=phrase.get(),
            )

        ctk.CTkButton(dialog, text="Generate", command=go).pack(pady=12)

    def _on_key_generated(self, payload: dict) -> None:
        dialog = getattr(self, "_gen_dialog", None)
        armor = payload.get("private_armor") or ""
        pub = payload.get("public_key_armor") or ""
        fp = payload.get("fingerprint") or ""
        if dialog is not None and dialog.winfo_exists():
            path = filedialog.asksaveasfilename(
                parent=dialog,
                title="Save private key (keep this file secret)",
                defaultextension=".asc",
                filetypes=[("ASCII armor", "*.asc"), ("All files", "*.*")],
            )
            if path and armor:
                with open(path, "w", encoding="utf-8") as handle:
                    handle.write(armor)
                pub_path = path.replace(".asc", ".pub.asc")
                if pub_path == path:
                    pub_path = path + ".pub"
                if pub:
                    with open(pub_path, "w", encoding="utf-8") as handle:
                        handle.write(pub)
            dialog.destroy()
        short = fp[-8:] if fp else "?"
        if hasattr(self, "key_var"):
            self.key_var.set(f"Private key loaded · {short}")
        self.unlocked = True
        self._set_status("Key generated.")
        self._render_chat()

    def _add_contact_dialog(self) -> None:
        dialog = ctk.CTkToplevel(self)
        dialog.title("Add contact")
        dialog.geometry("520x380")
        dialog.transient(self)
        dialog.grab_set()
        ctk.CTkLabel(dialog, text="Username").pack(anchor="w", padx=16, pady=(16, 4))
        user = ctk.CTkEntry(dialog)
        user.pack(fill="x", padx=16)
        ctk.CTkLabel(dialog, text="Their PGP public key (leave empty if they published one)").pack(
            anchor="w", padx=16, pady=(12, 4)
        )
        box = ctk.CTkTextbox(dialog, height=180)
        box.pack(fill="both", expand=True, padx=16, pady=6)

        def accept() -> None:
            username = user.get().strip()
            armor = box.get("1.0", "end").strip()
            if not username:
                messagebox.showerror("Contact", "Username required.", parent=dialog)
                return
            self.worker.submit("add_contact", username=username, public_key_armor=armor)
            dialog.destroy()

        ctk.CTkButton(dialog, text="Add", command=accept).pack(pady=12)

    def _remove_contact(self) -> None:
        if not self.selected_username:
            self._set_status("Select a contact to remove.")
            return
        self.worker.submit("delete_contact", username=self.selected_username)


def main() -> None:
    app = VaxChatApp()
    app.mainloop()


if __name__ == "__main__":
    main()
