from __future__ import annotations

import queue
import tkinter as tk
from tkinter import filedialog, messagebox

import customtkinter as ctk

from client.worker import BackgroundWorker

QUEUE_MS = 100
DEFAULT_SERVER = "http://127.0.0.1:8000"

# Telegram Desktop-inspired palette
COLOR_BG = "#0E1621"
COLOR_SIDEBAR = "#17212B"
COLOR_ACCENT = "#5288C1"
COLOR_BUBBLE_OUT = "#2B5278"
COLOR_BUBBLE_IN = "#182533"
COLOR_TEXT = "#F5F5F5"
COLOR_MUTED = "#7F91A4"
COLOR_INPUT = "#242F3D"


class VaxChatApp(ctk.CTk):
    def __init__(self) -> None:
        super().__init__()
        self.title("vaxchat")
        self.geometry("1000x660")
        self.minsize(860, 540)
        self.configure(fg_color=COLOR_BG)

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self._out: queue.Queue = queue.Queue()
        self.worker = BackgroundWorker(self._out)
        self.username: str | None = None
        self.rooms: list[dict] = []
        self.selected_room_id: int | None = None
        self.messages_by_room: dict[str, list[dict]] = {}
        self.unlocked = False
        self._busy = False
        self._queue_job: str | None = None
        self._server_url = DEFAULT_SERVER
        self._room_buttons: dict[int, ctk.CTkButton] = {}

        self.container = ctk.CTkFrame(self, fg_color=COLOR_BG)
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
            self.rooms = []
            self.selected_room_id = None
            self.messages_by_room = {}
            self.unlocked = False
            self._show_login()
        elif kind == "rooms":
            self.rooms = payload.get("rooms") or []
            self._redraw_rooms()
        elif kind == "invites":
            self._redraw_invites(payload.get("invites") or [])
        elif kind == "messages":
            self.messages_by_room = payload.get("messages_by_room") or {}
            self.unlocked = bool(payload.get("unlocked"))
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
                self.key_var.set(f"Key · {short}")
            self.unlocked = True
            self._render_chat()
        elif kind == "key_generated":
            self._on_key_generated(payload)
        elif kind == "room_opened":
            room_id = payload.get("room_id")
            if room_id is not None:
                self._select_room(int(room_id))

    def _show_login(self) -> None:
        self._clear_container()
        frame = ctk.CTkFrame(self.container, fg_color=COLOR_SIDEBAR, corner_radius=16)
        frame.place(relx=0.5, rely=0.5, anchor="center")

        ctk.CTkLabel(frame, text="vaxchat", font=ctk.CTkFont(size=28, weight="bold"), text_color=COLOR_TEXT).pack(
            padx=40, pady=(28, 4)
        )
        ctk.CTkLabel(
            frame,
            text="Encrypted rooms. The server only stores ciphertext.",
            text_color=COLOR_MUTED,
        ).pack(pady=(0, 16))

        self.server_entry = ctk.CTkEntry(frame, width=320, placeholder_text="Server URL", fg_color=COLOR_INPUT)
        self.server_entry.insert(0, self._server_url)
        self.server_entry.pack(padx=40, pady=6)

        self.user_entry = ctk.CTkEntry(frame, width=320, placeholder_text="Username", fg_color=COLOR_INPUT)
        self.user_entry.pack(padx=40, pady=6)

        self.pass_entry = ctk.CTkEntry(frame, width=320, placeholder_text="Password", show="•", fg_color=COLOR_INPUT)
        self.pass_entry.pack(padx=40, pady=6)

        btns = ctk.CTkFrame(frame, fg_color="transparent")
        btns.pack(pady=12)
        ctk.CTkButton(btns, text="Log in", width=140, fg_color=COLOR_ACCENT, command=lambda: self._auth(False)).pack(
            side="left", padx=6
        )
        ctk.CTkButton(
            btns, text="Register", width=140, fg_color=COLOR_BUBBLE_OUT, command=lambda: self._auth(True)
        ).pack(side="left", padx=6)

        self.login_status = ctk.CTkLabel(frame, text="", text_color=COLOR_MUTED)
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
        root = ctk.CTkFrame(self.container, fg_color=COLOR_BG)
        root.pack(fill="both", expand=True)
        root.grid_columnconfigure(1, weight=1)
        root.grid_rowconfigure(1, weight=1)

        top = ctk.CTkFrame(root, fg_color=COLOR_SIDEBAR, corner_radius=0, height=52)
        top.grid(row=0, column=0, columnspan=2, sticky="ew")
        self.key_var = tk.StringVar(value="Private key: not loaded")
        ctk.CTkLabel(top, text=f"{self.username}", font=ctk.CTkFont(weight="bold"), text_color=COLOR_TEXT).pack(
            side="left", padx=16, pady=12
        )
        ctk.CTkLabel(top, textvariable=self.key_var, text_color=COLOR_MUTED).pack(side="left", padx=8)
        ctk.CTkButton(top, text="Log out", width=80, fg_color=COLOR_INPUT, command=self._logout).pack(
            side="right", padx=12, pady=8
        )
        ctk.CTkButton(top, text="Generate keys", width=120, fg_color=COLOR_BUBBLE_OUT, command=self._generate_keys).pack(
            side="right", padx=4
        )
        ctk.CTkButton(top, text="Load key", width=100, fg_color=COLOR_ACCENT, command=self._load_key_dialog).pack(
            side="right", padx=4
        )

        left = ctk.CTkFrame(root, width=280, fg_color=COLOR_SIDEBAR, corner_radius=0)
        left.grid(row=1, column=0, sticky="nsw")
        left.grid_propagate(False)
        ctk.CTkLabel(left, text="Chats", font=ctk.CTkFont(size=16, weight="bold"), text_color=COLOR_TEXT).pack(
            anchor="w", padx=16, pady=(16, 8)
        )
        btnrow = ctk.CTkFrame(left, fg_color="transparent")
        btnrow.pack(fill="x", padx=12, pady=(0, 8))
        ctk.CTkButton(btnrow, text="New DM", width=80, fg_color=COLOR_ACCENT, command=self._new_dm_dialog).pack(
            side="left", padx=2
        )
        ctk.CTkButton(btnrow, text="New group", width=90, fg_color=COLOR_BUBBLE_OUT, command=self._new_group_dialog).pack(
            side="left", padx=2
        )
        self.room_list = ctk.CTkScrollableFrame(left, fg_color=COLOR_SIDEBAR, width=260)
        self.room_list.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        ctk.CTkLabel(left, text="Invites", font=ctk.CTkFont(size=14, weight="bold"), text_color=COLOR_MUTED).pack(
            anchor="w", padx=16, pady=(4, 4)
        )
        self.invite_list = ctk.CTkScrollableFrame(left, fg_color=COLOR_SIDEBAR, width=260, height=100)
        self.invite_list.pack(fill="x", padx=8, pady=(0, 12))

        right = ctk.CTkFrame(root, fg_color=COLOR_BG, corner_radius=0)
        right.grid(row=1, column=1, sticky="nsew")
        right.grid_rowconfigure(1, weight=1)
        right.grid_columnconfigure(0, weight=1)
        self.chat_title = ctk.CTkLabel(
            right, text="Select a chat", font=ctk.CTkFont(size=16, weight="bold"), text_color=COLOR_TEXT
        )
        self.chat_title.grid(row=0, column=0, sticky="w", padx=18, pady=(14, 6))

        self.history = ctk.CTkScrollableFrame(right, fg_color=COLOR_BG)
        self.history.grid(row=1, column=0, sticky="nsew", padx=10, pady=4)

        compose = ctk.CTkFrame(right, fg_color=COLOR_BG)
        compose.grid(row=2, column=0, sticky="ew", padx=14, pady=(6, 14))
        compose.grid_columnconfigure(0, weight=1)
        pill = ctk.CTkFrame(compose, fg_color=COLOR_INPUT, corner_radius=22)
        pill.grid(row=0, column=0, sticky="ew", padx=(0, 8))
        pill.grid_columnconfigure(0, weight=1)
        self.compose = ctk.CTkEntry(
            pill,
            placeholder_text="Message",
            fg_color="transparent",
            border_width=0,
            text_color=COLOR_TEXT,
        )
        self.compose.grid(row=0, column=0, sticky="ew", padx=14, pady=8)
        self.compose.bind("<Return>", lambda _e: self._send())
        ctk.CTkButton(compose, text="Send", width=84, corner_radius=18, fg_color=COLOR_ACCENT, command=self._send).grid(
            row=0, column=1
        )

        self.status_var = tk.StringVar(value="Ready")
        ctk.CTkLabel(root, textvariable=self.status_var, text_color=COLOR_MUTED, anchor="w").grid(
            row=2, column=0, columnspan=2, sticky="ew", padx=12, pady=(0, 8)
        )

        self._redraw_rooms()
        self.worker.submit("refresh_rooms")
        self.worker.submit("refresh_invites")

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

    def _room_label(self, room: dict) -> str:
        if room.get("is_direct"):
            for member in room.get("members") or []:
                if member.get("username") != self.username:
                    return member.get("username") or room.get("name") or "DM"
        return room.get("name") or f"Room {room.get('id')}"

    def _redraw_rooms(self) -> None:
        if not hasattr(self, "room_list"):
            return
        for child in self.room_list.winfo_children():
            child.destroy()
        self._room_buttons = {}
        for room in self.rooms:
            room_id = int(room["id"])
            label = self._room_label(room)
            active = room_id == self.selected_room_id
            btn = ctk.CTkButton(
                self.room_list,
                text=label,
                anchor="w",
                fg_color=COLOR_ACCENT if active else "transparent",
                hover_color=COLOR_BUBBLE_OUT,
                text_color=COLOR_TEXT,
                command=lambda rid=room_id: self._select_room(rid),
            )
            btn.pack(fill="x", pady=2, padx=4)
            self._room_buttons[room_id] = btn

    def _redraw_invites(self, invites: list[dict]) -> None:
        if not hasattr(self, "invite_list"):
            return
        for child in self.invite_list.winfo_children():
            child.destroy()
        if not invites:
            ctk.CTkLabel(self.invite_list, text="None", text_color=COLOR_MUTED, anchor="w").pack(
                fill="x", padx=4, pady=2
            )
            return
        for invite in invites:
            row = ctk.CTkFrame(self.invite_list, fg_color="transparent")
            row.pack(fill="x", pady=2)
            label = f"{invite.get('room_name')} · from {invite.get('inviter_username')}"
            ctk.CTkLabel(row, text=label, text_color=COLOR_TEXT, anchor="w").pack(side="left", padx=4)
            iid = int(invite["id"])
            ctk.CTkButton(
                row,
                text="Join",
                width=48,
                fg_color=COLOR_ACCENT,
                command=lambda invite_id=iid: self.worker.submit("accept_invite", invite_id=invite_id),
            ).pack(side="right", padx=2)
            ctk.CTkButton(
                row,
                text="×",
                width=28,
                fg_color=COLOR_INPUT,
                command=lambda invite_id=iid: self.worker.submit("decline_invite", invite_id=invite_id),
            ).pack(side="right", padx=2)

    def _select_room(self, room_id: int) -> None:
        self.selected_room_id = room_id
        room = next((r for r in self.rooms if int(r["id"]) == room_id), None)
        title = self._room_label(room) if room else f"Room {room_id}"
        if hasattr(self, "chat_title"):
            self.chat_title.configure(text=title)
        self._redraw_rooms()
        self.worker.submit("select_room", room_id=room_id)
        self._render_chat()

    def _render_chat(self) -> None:
        if not hasattr(self, "history"):
            return
        for child in self.history.winfo_children():
            child.destroy()
        if self.selected_room_id is None:
            return
        if not self.unlocked:
            ctk.CTkLabel(
                self.history,
                text="Load your private key to decrypt this conversation.",
                text_color=COLOR_MUTED,
            ).pack(anchor="w", padx=8, pady=8)
        rows = self.messages_by_room.get(str(self.selected_room_id), [])
        if not rows and self.unlocked:
            ctk.CTkLabel(self.history, text="No messages yet.", text_color=COLOR_MUTED).pack(anchor="w", padx=8, pady=8)
        for row in rows:
            outgoing = bool(row.get("is_outgoing"))
            wrap = ctk.CTkFrame(self.history, fg_color="transparent")
            wrap.pack(fill="x", pady=4, padx=6)
            bubble = ctk.CTkFrame(
                wrap,
                fg_color=COLOR_BUBBLE_OUT if outgoing else COLOR_BUBBLE_IN,
                corner_radius=12,
            )
            if outgoing:
                bubble.pack(anchor="e", padx=(80, 4))
            else:
                bubble.pack(anchor="w", padx=(4, 80))
            who = row.get("who") or "?"
            mark = row.get("mark") or ""
            text = row.get("text") or ""
            ctk.CTkLabel(
                bubble,
                text=f"{who}{mark}",
                text_color=COLOR_MUTED,
                font=ctk.CTkFont(size=11),
                anchor="w",
            ).pack(anchor="w", padx=12, pady=(8, 0))
            ctk.CTkLabel(
                bubble,
                text=text,
                text_color=COLOR_TEXT,
                wraplength=420,
                justify="left",
                anchor="w",
            ).pack(anchor="w", padx=12, pady=(2, 10))

    def _send(self) -> None:
        if self._busy:
            return
        room_id = self.selected_room_id
        text = self.compose.get().strip()
        if room_id is None:
            self._set_status("Select a chat first.")
            return
        if not text:
            return
        if not self.unlocked:
            self._set_status("Load your private key before sending.")
            return
        self.compose.delete(0, "end")
        self._busy = True
        self._set_status("Encrypting…")
        self.worker.submit("send", room_id=room_id, text=text)

    def _new_dm_dialog(self) -> None:
        dialog = ctk.CTkToplevel(self)
        dialog.title("New DM")
        dialog.geometry("520x420")
        dialog.configure(fg_color=COLOR_SIDEBAR)
        dialog.transient(self)
        dialog.grab_set()
        ctk.CTkLabel(dialog, text="Peer username", text_color=COLOR_TEXT).pack(anchor="w", padx=16, pady=(16, 4))
        user = ctk.CTkEntry(dialog, fg_color=COLOR_INPUT)
        user.pack(fill="x", padx=16)
        ctk.CTkLabel(
            dialog,
            text="Their PGP public key (required unless they already published one)",
            text_color=COLOR_TEXT,
        ).pack(anchor="w", padx=16, pady=(12, 4))
        box = ctk.CTkTextbox(dialog, height=200, fg_color=COLOR_INPUT)
        box.pack(fill="both", expand=True, padx=16, pady=6)

        def accept() -> None:
            peer = user.get().strip()
            armor = box.get("1.0", "end").strip()
            if not peer:
                messagebox.showerror("DM", "Username required.", parent=dialog)
                return
            self.worker.submit("create_dm", peer_username=peer, public_key_armor=armor)
            dialog.destroy()

        ctk.CTkButton(dialog, text="Open", fg_color=COLOR_ACCENT, command=accept).pack(pady=16)

    def _new_group_dialog(self) -> None:
        dialog = ctk.CTkToplevel(self)
        dialog.title("New group")
        dialog.geometry("420x260")
        dialog.configure(fg_color=COLOR_SIDEBAR)
        dialog.transient(self)
        dialog.grab_set()
        ctk.CTkLabel(dialog, text="Group name", text_color=COLOR_TEXT).pack(anchor="w", padx=16, pady=(16, 4))
        name = ctk.CTkEntry(dialog, fg_color=COLOR_INPUT)
        name.pack(fill="x", padx=16)
        ctk.CTkLabel(
            dialog,
            text="Invitees (comma-separated; they must accept)",
            text_color=COLOR_TEXT,
        ).pack(anchor="w", padx=16, pady=(12, 4))
        members = ctk.CTkEntry(dialog, fg_color=COLOR_INPUT)
        members.pack(fill="x", padx=16)

        def accept() -> None:
            names = [n.strip() for n in members.get().split(",") if n.strip()]
            self.worker.submit("create_group", name=name.get().strip(), member_usernames=names)
            dialog.destroy()

        ctk.CTkButton(dialog, text="Create & invite", fg_color=COLOR_ACCENT, command=accept).pack(pady=16)

    def _load_key_dialog(self) -> None:
        dialog = ctk.CTkToplevel(self)
        dialog.title("Load private key")
        dialog.geometry("520x420")
        dialog.configure(fg_color=COLOR_SIDEBAR)
        dialog.transient(self)
        dialog.grab_set()
        ctk.CTkLabel(dialog, text="Paste an ASCII-armored private key, or open a file.", text_color=COLOR_TEXT).pack(
            padx=16, pady=(16, 8)
        )
        box = ctk.CTkTextbox(dialog, height=220, fg_color=COLOR_INPUT)
        box.pack(fill="both", expand=True, padx=16, pady=8)
        phrase = ctk.CTkEntry(dialog, placeholder_text="Passphrase", show="•", fg_color=COLOR_INPUT)
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
        ctk.CTkButton(row, text="Open file…", fg_color=COLOR_BUBBLE_OUT, command=from_file).pack(side="left", padx=6)
        ctk.CTkButton(row, text="Unlock", fg_color=COLOR_ACCENT, command=accept).pack(side="left", padx=6)

    def _generate_keys(self) -> None:
        dialog = ctk.CTkToplevel(self)
        dialog.title("Generate keypair")
        dialog.geometry("420x240")
        dialog.configure(fg_color=COLOR_SIDEBAR)
        dialog.transient(self)
        dialog.grab_set()
        ctk.CTkLabel(dialog, text="An Ed25519/Cv25519 key will be created locally.", text_color=COLOR_TEXT).pack(
            padx=16, pady=(16, 8)
        )
        name = ctk.CTkEntry(dialog, placeholder_text="Name on the key", fg_color=COLOR_INPUT)
        name.insert(0, self.username or "vaxchat")
        name.pack(fill="x", padx=16, pady=6)
        phrase = ctk.CTkEntry(dialog, placeholder_text="Optional passphrase", show="•", fg_color=COLOR_INPUT)
        phrase.pack(fill="x", padx=16, pady=6)
        status = ctk.CTkLabel(dialog, text="", text_color=COLOR_MUTED)
        status.pack(pady=4)
        self._gen_dialog = dialog
        self._gen_status = status

        def go() -> None:
            status.configure(text="Generating…")
            self.worker.submit(
                "generate_key",
                name=name.get().strip() or "vaxchat",
                passphrase=phrase.get(),
            )

        ctk.CTkButton(dialog, text="Generate", fg_color=COLOR_ACCENT, command=go).pack(pady=12)

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
            self.key_var.set(f"Key · {short}")
        self.unlocked = True
        self._set_status("Key generated.")
        self._render_chat()


def main() -> None:
    app = VaxChatApp()
    app.mainloop()


if __name__ == "__main__":
    main()
