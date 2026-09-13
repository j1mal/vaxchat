from typing import Any
from urllib.parse import urlparse

import httpx


class ApiError(Exception):
    pass


class ChatApi:
    """HTTP client for the ciphertext relay. Do not pass private keys into this class."""

    def __init__(self, base_url: str = "http://127.0.0.1:8000") -> None:
        self.base_url = base_url.rstrip("/")
        self.token: str | None = None
        self.username: str | None = None
        self._http = httpx.Client(timeout=20.0)

    def close(self) -> None:
        self._http.close()

    def ws_base(self) -> str:
        parsed = urlparse(self.base_url)
        scheme = "wss" if parsed.scheme == "https" else "ws"
        netloc = parsed.netloc or "127.0.0.1:8000"
        return f"{scheme}://{netloc}"

    def _headers(self) -> dict[str, str]:
        if not self.token:
            return {}
        return {"Authorization": f"Bearer {self.token}"}

    def _parse(self, response: httpx.Response) -> Any:
        if response.is_success:
            if response.status_code == 204 or not response.content:
                return None
            return response.json()
        detail: Any
        try:
            payload = response.json()
            detail = payload.get("detail", payload)
        except Exception:
            detail = response.text
        raise ApiError(str(detail))

    def register(self, username: str, password: str) -> dict:
        data = self._parse(
            self._http.post(f"{self.base_url}/auth/register", json={"username": username, "password": password})
        )
        self.token = data["access_token"]
        self.username = data["username"]
        return data

    def login(self, username: str, password: str) -> dict:
        data = self._parse(
            self._http.post(f"{self.base_url}/auth/login", json={"username": username, "password": password})
        )
        self.token = data["access_token"]
        self.username = data["username"]
        return data

    def logout(self) -> None:
        if self.token:
            try:
                self._http.post(f"{self.base_url}/auth/logout", headers=self._headers())
            except Exception:
                pass
        self.token = None
        self.username = None

    def me(self) -> dict:
        return self._parse(self._http.get(f"{self.base_url}/me", headers=self._headers()))

    def publish_public_key(self, public_key_armor: str) -> dict:
        return self._parse(
            self._http.put(f"{self.base_url}/me", headers=self._headers(), json={"public_key_armor": public_key_armor})
        )

    def list_contacts(self) -> list[dict]:
        return self._parse(self._http.get(f"{self.base_url}/contacts", headers=self._headers()))

    def add_contact(self, username: str, public_key_armor: str = "") -> dict:
        return self._parse(
            self._http.post(
                f"{self.base_url}/contacts",
                headers=self._headers(),
                json={"username": username, "public_key_armor": public_key_armor},
            )
        )

    def delete_contact(self, username: str) -> None:
        self._parse(self._http.delete(f"{self.base_url}/contacts/{username}", headers=self._headers()))

    def list_rooms(self) -> list[dict]:
        return self._parse(self._http.get(f"{self.base_url}/rooms", headers=self._headers()))

    def create_dm(self, peer_username: str) -> dict:
        return self._parse(
            self._http.post(
                f"{self.base_url}/rooms",
                headers=self._headers(),
                json={"peer_username": peer_username},
            )
        )

    def create_group(self, name: str, member_usernames: list[str]) -> dict:
        return self._parse(
            self._http.post(
                f"{self.base_url}/rooms",
                headers=self._headers(),
                json={"name": name, "member_usernames": member_usernames},
            )
        )

    def list_invites(self) -> list[dict]:
        return self._parse(self._http.get(f"{self.base_url}/rooms/invites", headers=self._headers()))

    def accept_invite(self, invite_id: int) -> dict:
        return self._parse(
            self._http.post(f"{self.base_url}/rooms/invites/{invite_id}/accept", headers=self._headers())
        )

    def decline_invite(self, invite_id: int) -> None:
        self._parse(
            self._http.post(f"{self.base_url}/rooms/invites/{invite_id}/decline", headers=self._headers())
        )

    def room_members(self, room_id: int) -> list[dict]:
        return self._parse(self._http.get(f"{self.base_url}/rooms/{room_id}/members", headers=self._headers()))

    def send_room_message(self, room_id: int, ciphertext: str) -> dict:
        return self._parse(
            self._http.post(
                f"{self.base_url}/rooms/{room_id}/messages",
                headers=self._headers(),
                json={"ciphertext": ciphertext},
            )
        )

    def list_room_messages(self, room_id: int, after_id: int = 0) -> list[dict]:
        return self._parse(
            self._http.get(
                f"{self.base_url}/rooms/{room_id}/messages",
                headers=self._headers(),
                params={"after_id": after_id},
            )
        )
