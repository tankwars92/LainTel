#!/usr/bin/env python3

from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Optional

API_VERSION = "5.131"
CLIENT_NAME = "LainTel"
USER_AGENT = "LainTel/1.0"
USER_FIELDS = (
    "status,screen_name,friend_status,online,city,home_town,about,"
    "bdate,sex,counters,last_seen,site,interests"
)


class OvkApiError(Exception):
    def __init__(self, message: str, code: Optional[int] = None, payload: Optional[dict] = None):
        super().__init__(message)
        self.code = code
        self.payload = payload or {}


def normalize_instance(url: str) -> str:
    url = (url or "").strip()
    if not url:
        raise OvkApiError("Пустой адрес инстанса")
    if "://" not in url:
        url = "https://" + url
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise OvkApiError("Некорректный URL инстанса")
    return parsed.scheme + "://" + parsed.netloc


class OvkApi:
    def __init__(self, instance: str, timeout: float = 25.0):
        self.instance = normalize_instance(instance)
        self.timeout = timeout
        self.access_token: Optional[str] = None
        self.user_id: Optional[int] = None
        self.user_name: Optional[str] = None
        self._ctx = ssl.create_default_context()

    def _request(self, path: str, fields: dict[str, Any]) -> dict[str, Any]:
        body = urllib.parse.urlencode(
            {k: v for k, v in fields.items() if v is not None},
            doseq=True,
        ).encode("utf-8")
        url = self.instance.rstrip("/") + path
        req = urllib.request.Request(
            url,
            data=body,
            method="POST",
            headers={
                "User-Agent": USER_AGENT,
                "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
                "Accept": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self._ctx) as resp:
                raw = resp.read()
                status = resp.status
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            status = exc.code
        except urllib.error.URLError as exc:
            raise OvkApiError(f"Не удалось подключиться к {self.instance}: {exc.reason}") from exc

        try:
            data = json.loads(raw.decode("utf-8", "replace") or "{}")
        except json.JSONDecodeError as exc:
            snippet = raw[:180].decode("utf-8", "replace")
            raise OvkApiError(f"Инстанс вернул не JSON (HTTP {status}): {snippet}") from exc

        if not isinstance(data, dict):
            raise OvkApiError("Неожиданный ответ API")
        return data

    def _unwrap(self, data: dict[str, Any]) -> Any:
        if "error" in data and isinstance(data["error"], dict):
            err = data["error"]
            raise OvkApiError(
                str(err.get("error_msg") or err.get("error_description") or "API error"),
                code=err.get("error_code"),
                payload=data,
            )
        if data.get("error") == "need_validation":
            raise OvkApiError("need_validation", payload=data)
        if "error_code" in data and "response" not in data:
            raise OvkApiError(
                str(data.get("error_msg") or "API error"),
                code=data.get("error_code"),
                payload=data,
            )
        if "response" in data:
            return data["response"]
        return data

    def probe(self) -> str:
        try:
            version = self.call("ovk.version")
        except OvkApiError:
            ts = self.call("utils.getServerTime")
            return f"OpenVK-совместимый API (time={ts})"
        if isinstance(version, str):
            return version
        return json.dumps(version, ensure_ascii=False)

    def call(self, method: str, **params: Any) -> Any:
        fields: dict[str, Any] = {"v": API_VERSION, **params}
        if self.access_token:
            fields["access_token"] = self.access_token
        data = self._request("/method/" + method, fields)
        return self._unwrap(data)

    def login(self, username: str, password: str, code: Optional[str] = None) -> dict[str, Any]:
        fields: dict[str, Any] = {
            "grant_type": "password",
            "username": username,
            "password": password,
            "client_name": CLIENT_NAME,
            "v": API_VERSION,
        }
        if code:
            fields["code"] = code
        data = self._request("/token", fields)
        if data.get("error") == "need_validation" or data.get("validation_type"):
            raise OvkApiError("need_validation", payload=data)
        unwrapped = self._unwrap(data)
        if not isinstance(unwrapped, dict) or not unwrapped.get("access_token"):
            raise OvkApiError("Инстанс не выдал access_token")
        self.access_token = str(unwrapped["access_token"])
        self.user_id = int(unwrapped.get("user_id") or 0) or None
        self._load_me()
        return unwrapped

    def _load_me(self) -> None:
        me = self.call("users.get", fields="screen_name")
        if isinstance(me, list) and me:
            u = me[0]
            first = u.get("first_name") or ""
            last = u.get("last_name") or ""
            self.user_name = (first + " " + last).strip() or u.get("screen_name")
            self.user_id = int(u.get("id") or self.user_id or 0) or self.user_id

    def newsfeed(self, count: int = 15, start_from: str = "", global_feed: bool = False) -> dict[str, Any]:
        method = "newsfeed.getGlobal" if global_feed else "newsfeed.get"
        result = self.call(
            method,
            count=max(1, min(50, count)),
            offset=0,
            start_from=start_from or "",
            extended=1,
            filters="post",
            fields="screen_name",
        )
        if isinstance(result, list):
            return {"items": result, "profiles": [], "groups": []}
        if not isinstance(result, dict):
            return {"items": [], "profiles": [], "groups": []}
        return result

    def wall_post(self, message: str, owner_id: Optional[int] = None) -> int:
        oid = owner_id if owner_id is not None else self.user_id
        if oid is None:
            raise OvkApiError("Сначала войдите в аккаунт")
        result = self.call("wall.post", owner_id=oid, message=message)
        if isinstance(result, dict) and "post_id" in result:
            return int(result["post_id"])
        raise OvkApiError("Не удалось опубликовать пост")

    def wall_comments(self, owner_id: int, post_id: int, offset: int = 0, count: int = 40) -> dict[str, Any]:
        result = self.call(
            "wall.getComments",
            owner_id=owner_id,
            post_id=post_id,
            offset=max(0, offset),
            count=max(1, min(100, count)),
            need_likes=1,
            extended=1,
            sort="asc",
            fields="screen_name",
        )
        if not isinstance(result, dict):
            return {"count": 0, "items": [], "profiles": [], "groups": []}
        return result

    def wall_create_comment(self, owner_id: int, post_id: int, message: str) -> int:
        result = self.call(
            "wall.createComment",
            owner_id=owner_id,
            post_id=post_id,
            message=message,
        )
        if isinstance(result, dict) and "comment_id" in result:
            return int(result["comment_id"])
        raise OvkApiError("Не удалось отправить комментарий")

    def messages_conversations(self, offset: int = 0, count: int = 20) -> dict[str, Any]:
        result = self.call(
            "messages.getConversations",
            offset=max(0, offset),
            count=max(1, min(50, count)),
            filter="all",
            extended=1,
            fields="screen_name",
        )
        if not isinstance(result, dict):
            return {"count": 0, "items": [], "profiles": []}
        return result

    def messages_history(self, peer_id: int, offset: int = 0, count: int = 30) -> dict[str, Any]:
        result = self.call(
            "messages.getHistory",
            peer_id=peer_id,
            user_id=peer_id,
            offset=max(0, offset),
            count=max(1, min(50, count)),
            rev=0,
            extended=1,
            fields="screen_name",
        )
        if not isinstance(result, dict):
            return {"count": 0, "items": [], "profiles": []}
        return result

    def messages_send(self, peer_id: int, message: str) -> int:
        result = self.call("messages.send", user_id=peer_id, peer_id=peer_id, message=message)
        try:
            return int(result)
        except (TypeError, ValueError):
            raise OvkApiError("Не удалось отправить сообщение")

    def resolve_screen_name(self, name: str) -> Optional[int]:
        name = (name or "").strip()
        if not name:
            return None
        if name.isdigit():
            return int(name)
        if name.lower().startswith("id") and name[2:].isdigit():
            return int(name[2:])
        result = self.call("utils.resolveScreenName", screen_name=name)
        if isinstance(result, dict) and result.get("type") == "user":
            return int(result.get("object_id") or 0) or None
        return None

    def users_get(self, user_ids: str, fields: str = USER_FIELDS) -> list[dict]:
        result = self.call("users.get", user_ids=str(user_ids), fields=fields)
        if isinstance(result, list):
            return [u for u in result if isinstance(u, dict)]
        return []

    def friends_get(self, user_id: int = 0, offset: int = 0, count: int = 30) -> dict[str, Any]:
        result = self.call(
            "friends.get",
            user_id=user_id,
            fields="status,online,screen_name,friend_status",
            offset=max(0, offset),
            count=max(1, min(100, count)),
        )
        if not isinstance(result, dict):
            return {"count": 0, "items": []}
        return result

    def friends_get_requests(self, out: int = 0, offset: int = 0, count: int = 50) -> dict[str, Any]:
        result = self.call(
            "friends.getRequests",
            out=1 if out else 0,
            offset=max(0, offset),
            count=max(1, min(100, count)),
            fields="status,online,screen_name,friend_status",
        )
        if not isinstance(result, dict):
            return {"count": 0, "items": []}
        return result

    def friends_add(self, user_id: int) -> int:
        result = self.call("friends.add", user_id=str(user_id))
        try:
            return int(result)
        except (TypeError, ValueError):
            raise OvkApiError("friends.add failed")

    def friends_delete(self, user_id: int) -> int:
        result = self.call("friends.delete", user_id=str(user_id))
        try:
            return int(result)
        except (TypeError, ValueError):
            raise OvkApiError("friends.delete failed")

    def wall_get(self, owner_id: int, offset: int = 0, count: int = 15) -> dict[str, Any]:
        result = self.call(
            "wall.get",
            owner_id=owner_id,
            offset=max(0, offset),
            count=max(1, min(50, count)),
            extended=1,
            filter="all",
        )
        if not isinstance(result, dict):
            return {"count": 0, "items": [], "profiles": [], "groups": []}
        return result

    def logout(self) -> None:
        self.access_token = None
        self.user_id = None
        self.user_name = None
