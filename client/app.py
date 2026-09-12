from __future__ import annotations

import threading
import tkinter as tk
from tkinter import filedialog, messagebox
import customtkinter as ctk

from client.api import ApiError, ChatApi
from client.crypto import CryptoError, CryptoSession

POLL_MS = 3000
DEFAULT_SERVER = "http://127.0.0.1:8000"


class VaxChatApp(ctk.CTk):
    def __init__(self) -> None:
        super().__init__()
        self.title("vaxchat")
        self.geometry("980x640")
        self.minsize(820, 520)

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self.api = ChatApi(DEFAULT_SERVER)
        self.crypto = CryptoSession()
        self.contacts: list[dict] = []
        self.selected_username: str | None = None
        self.messages_by_peer: dict[str, list[dict]] = {}
        self.seen_ids: set[int] = set()
        self.after_id = 0
        self._poll_job: str | None = None
        self._busy = False

        self.container = ctk.CTkFrame(self, fg_color="transparent")
        self.container.pack(fill="both", expand=True)
        self._show_login()
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _clear_container(self) -> None:
        for child in self.container.winfo_children():
            child.destroy()

    def _set_status(self, text: str) -> None:
        if hasattr(self, "status_var"):
            self.status_var.set(text)

    def _show_login(self) -> None:
        self._stop_poll()
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
        self.server_entry.insert(0, self.api.base_url)
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
        self.api.base_url = server.rstrip("/")
        self.login_status.configure(text="Working…")
        self._busy = True

        def work() -> None:
            try:
                if register:
                    self.api.register(username, password)
                else:
                    self.api.login(username, password)
                err = None
            except Exception as exc:
                err = str(exc)
            self.after(0, lambda: self._auth_done(err))

        threading.Thread(target=work, daemon=True).start()

    def _auth_done(self, err: str | None) -> None:
        self._busy = False
        if err:
            self.login_status.configure(text=err)
            return
        self._show_main()

    def _show_main(self) -> None:
        self._clear_container()
        root = ctk.CTkFrame(self.container, fg_color="transparent")
        root.pack(fill="both", expand=True, padx=12, pady=12)
        root.grid_columnconfigure(1, weight=1)
        root.grid_rowconfigure(1, weight=1)

        top = ctk.CTkFrame(root)
        top.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 8))
        self.key_var = tk.StringVar(value="Private key: not loaded")
        ctk.CTkLabel(top, text=f"Signed in as {self.api.username}", font=ctk.CTkFont(weight="bold")).pack(
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

        self._refresh_contacts()
        self._start_poll()

    def _logout(self) -> None:
        self._stop_poll()
        self.api.logout()
        self.crypto.clear()
        self.contacts = []
        self.selected_username = None
        self.messages_by_peer = {}
        self.seen_ids = set()
        self.after_id = 0
        self._show_login()

    def _on_close(self) -> None:
        self._stop_poll()
        self.crypto.clear()
        self.api.close()
        self.destroy()

    def _start_poll(self) -> None:
        self._stop_poll()
        self._poll()

    def _stop_poll(self) -> None:
        if self._poll_job is not None:
            try:
                self.after_cancel(self._poll_job)
            except Exception:
                pass
            self._poll_job = None

    def _ingest_messages(self, rows: list[dict]) -> None:
        for row in rows:
            msg_id = row["id"]
            if msg_id in self.seen_ids:
                continue
            self.seen_ids.add(msg_id)
            # Outgoing: partner is other_username. Incoming: partner is sender
            # (also repairs older rows that wrongly set other_user_id to self).
            if row.get("is_outgoing"):
                peer = row["other_username"]
            else:
                peer = row["sender_username"]
            self.messages_by_peer.setdefault(peer, []).append(row)
            self.after_id = max(self.after_id, msg_id)

    def _poll(self) -> None:
        def work() -> None:
            try:
                rows = self.api.list_messages(after_id=self.after_id)
                err = None
            except Exception as exc:
                rows = []
                err = str(exc)
            self.after(0, lambda: self._poll_done(rows, err))

        threading.Thread(target=work, daemon=True).start()

    def _poll_done(self, rows: list[dict], err: str | None) -> None:
        if err:
            self._set_status(f"Poll failed: {err}")
        else:
            if rows:
                self._ingest_messages(rows)
                if self.selected_username:
                    self._render_chat()
            self._set_status(f"Polling {self.api.base_url} · last id {self.after_id}")
        self._poll_job = self.after(POLL_MS, self._poll)

    def _refresh_contacts(self) -> None:
        def work() -> None:
            try:
                rows = self.api.list_contacts()
                err = None
            except Exception as exc:
                rows = []
                err = str(exc)
            self.after(0, lambda: self._contacts_done(rows, err))

        threading.Thread(target=work, daemon=True).start()

    def _contacts_done(self, rows: list[dict], err: str | None) -> None:
        if err:
            self._set_status(err)
            return
        self.contacts = rows
        for child in self.contact_list.winfo_children():
            child.destroy()
        for contact in rows:
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

    def _contact_pubkey(self, username: str) -> str | None:
        for contact in self.contacts:
            if contact["username"] == username:
                return contact["public_key_armor"]
        return None

    def _render_chat(self) -> None:
        self.history.configure(state="normal")
        self.history.delete("1.0", "end")
        if not self.selected_username:
            self.history.configure(state="disabled")
            return
        rows = self.messages_by_peer.get(self.selected_username, [])
        if not self.crypto.unlocked:
            self.history.insert("end", "Load your private key to decrypt this conversation.\n")
            self.history.configure(state="disabled")
            return
        if not rows:
            self.history.insert("end", "No messages yet.\n")
        for row in rows:
            who = "you" if row["is_outgoing"] else row["sender_username"]
            sender_pub = None if row["is_outgoing"] else self._contact_pubkey(row["sender_username"])
            try:
                text, verified = self.crypto.decrypt(row["ciphertext"], sender_pub)
                mark = ""
                if verified is True:
                    mark = " ✓"
                elif verified is False:
                    mark = " (signature not verified)"
                self.history.insert("end", f"{who}{mark}: {text}\n")
            except CryptoError:
                self.history.insert("end", f"{who}: [could not decrypt]\n")
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
        if not self.crypto.unlocked:
            self._set_status("Load your private key before sending.")
            return
        their_pub = self._contact_pubkey(peer)
        my_pub = self.crypto.public_key_armor
        if not their_pub or not my_pub:
            self._set_status("Missing a public key for this conversation.")
            return
        self.compose.delete(0, "end")
        self._busy = True
        self._set_status("Encrypting…")

        def work() -> None:
            try:
                to_them = self.crypto.encrypt_for(text, their_pub)
                to_me = self.crypto.encrypt_for(text, my_pub)
                rows = self.api.send_message(peer, to_them, to_me)
                err = None
            except Exception as exc:
                rows = []
                err = str(exc)
            self.after(0, lambda: self._send_done(rows, err))

        threading.Thread(target=work, daemon=True).start()

    def _send_done(self, rows: list[dict], err: str | None) -> None:
        self._busy = False
        if err:
            self._set_status(err)
            return
        self._ingest_messages(rows)
        self._render_chat()
        self._set_status("Sent.")

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
            try:
                self.crypto.load_private(armor, phrase.get())
            except CryptoError as exc:
                messagebox.showerror("Key", str(exc), parent=dialog)
                return
            self._after_key_loaded()
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
        ctk.CTkLabel(dialog, text="A 2048-bit RSA key will be created on this machine.").pack(padx=16, pady=(16, 8))
        name = ctk.CTkEntry(dialog, placeholder_text="Name on the key")
        name.insert(0, self.api.username or "vaxchat")
        name.pack(fill="x", padx=16, pady=6)
        phrase = ctk.CTkEntry(dialog, placeholder_text="Optional passphrase", show="•")
        phrase.pack(fill="x", padx=16, pady=6)
        status = ctk.CTkLabel(dialog, text="")
        status.pack(pady=4)

        def go() -> None:
            status.configure(text="Generating… this can take a few seconds.")
            dialog.update_idletasks()

            def work() -> None:
                try:
                    armor = self.crypto.generate(name.get().strip() or "vaxchat", phrase.get())
                    err = None
                except Exception as exc:
                    armor = ""
                    err = str(exc)
                self.after(0, lambda: done(armor, err))

            threading.Thread(target=work, daemon=True).start()

            def done(armor: str, err: str | None) -> None:
                if err:
                    status.configure(text=err)
                    return
                path = filedialog.asksaveasfilename(
                    parent=dialog,
                    title="Save private key (keep this file secret)",
                    defaultextension=".asc",
                    filetypes=[("ASCII armor", "*.asc"), ("All files", "*.*")],
                )
                if path:
                    with open(path, "w", encoding="utf-8") as handle:
                        handle.write(armor)
                    pub_path = path.replace(".asc", ".pub.asc")
                    if pub_path == path:
                        pub_path = path + ".pub"
                    if self.crypto.public_key_armor:
                        with open(pub_path, "w", encoding="utf-8") as handle:
                            handle.write(self.crypto.public_key_armor)
                self._after_key_loaded()
                dialog.destroy()

        ctk.CTkButton(dialog, text="Generate", command=go).pack(pady=12)

    def _after_key_loaded(self) -> None:
        fp = self.crypto.fingerprint or ""
        short = fp[-8:] if fp else "?"
        self.key_var.set(f"Private key loaded · {short}")
        if self.crypto.public_key_armor:
            def work() -> None:
                try:
                    self.api.publish_public_key(self.crypto.public_key_armor or "")
                    err = None
                except Exception as exc:
                    err = str(exc)
                self.after(0, lambda: self._set_status("Public key published." if not err else err))

            threading.Thread(target=work, daemon=True).start()
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

            def work() -> None:
                try:
                    self.api.add_contact(username, armor)
                    err = None
                except Exception as exc:
                    err = str(exc)
                self.after(0, lambda: done(err))

            def done(err: str | None) -> None:
                if err:
                    messagebox.showerror("Contact", err, parent=dialog)
                    return
                dialog.destroy()
                self._refresh_contacts()

            threading.Thread(target=work, daemon=True).start()

        ctk.CTkButton(dialog, text="Add", command=accept).pack(pady=12)

    def _remove_contact(self) -> None:
        if not self.selected_username:
            self._set_status("Select a contact to remove.")
            return
        name = self.selected_username

        def work() -> None:
            try:
                self.api.delete_contact(name)
                err = None
            except Exception as exc:
                err = str(exc)
            self.after(0, lambda: done(err))

        def done(err: str | None) -> None:
            if err:
                self._set_status(err)
                return
            self.selected_username = None
            self.chat_title.configure(text="Select a contact")
            self._refresh_contacts()
            self._render_chat()

        threading.Thread(target=work, daemon=True).start()


def main() -> None:
    app = VaxChatApp()
    app.mainloop()


if __name__ == "__main__":
    main()
