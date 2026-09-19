#!/usr/bin/env python3

from __future__ import annotations

import argparse
import getpass
import html
import json
import os
import re
import socket
import sys
import threading
import time
from datetime import datetime, timezone
from typing import Any, Optional

from ovk_api import OvkApi, OvkApiError, normalize_instance

IAC, DONT, DO, WONT, WILL, SB, SE, GA = 255, 254, 253, 252, 251, 250, 240, 249
ECHO, SGA, BINARY, NAWS = 1, 3, 0, 31

H, V = "\u2550", "\u2551"
TL, TR, BL, BR = "\u2554", "\u2557", "\u255a", "\u255d"
ML, MR = "\u2560", "\u2563"

STATE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "laintel.state")
SAMPLE = "Privet / \u041f\u0440\u0438\u0432\u0435\u0442 / \u042f"

CODEPAGES = [
    ("1", "utf-8", "UTF-8  (PuTTY)"),
    ("2", "cp866", "CP866  (telnet.exe)"),
    ("3", "cp1251", "CP1251 (Windows)"),
]


def _enc_name(name: str) -> str:
    aliases = {
        "oem": "cp866",
        "dos": "cp866",
        "866": "cp866",
        "win": "cp1251",
        "1251": "cp1251",
        "utf8": "utf-8",
        "utf-8": "utf-8",
    }
    key = (name or "").strip().lower()
    return aliases.get(key, name.strip() if name else "utf-8")


def _load_state() -> dict:
    try:
        with open(STATE_PATH, encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _save_state(data: dict) -> None:
    prev = _load_state()
    prev.update(data)
    try:
        with open(STATE_PATH, "w", encoding="utf-8") as fh:
            json.dump(prev, fh)
    except OSError:
        pass


def _hexdump(data: bytes, limit: int = 240) -> str:
    raw = data[:limit]
    hx = " ".join("%02X" % b for b in raw)
    vis = "".join(chr(b) if 32 <= b < 127 else "." for b in raw)
    extra = " ..." if len(data) > limit else ""
    return "%s  |%s|%s" % (hx, vis, extra)

def _strip_html(text: str) -> str:
    text = str(text or "")
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = text.replace("\t", "    ")
    text = re.sub(r"(?i)<br\s*/?>", "\n", text)
    text = re.sub(r"(?i)</p>", "\n", text)
    text = re.sub(r"<[^>]+>", "", text)
    text = html.unescape(text)
    text = "".join(ch if (ch == "\n" or ord(ch) >= 32) else " " for ch in text)
    return text.strip()


def _apply_markup(text: str, enabled: bool) -> str:
    if not enabled:
        return text

    def wrap(code: str):
        def repl(m: re.Match) -> str:
            return "\x1b[%sm%s\x1b[0m" % (code, m.group(1))

        return repl

    text = re.sub(r"~~(.+?)~~", wrap("9"), text, flags=re.S)
    text = re.sub(r"\*\*(.+?)\*\*", wrap("1"), text, flags=re.S)
    text = re.sub(r"__(.+?)__", wrap("4"), text, flags=re.S)
    text = re.sub(r"(?<!\*)\*(?!\*)(.+?)(?<!\*)\*(?!\*)", wrap("3"), text, flags=re.S)
    return text


def _wrap_vis(text: str, width: int) -> list[str]:
    width = max(20, width)
    lines: list[str] = []
    for para in text.split("\n"):
        if not para.strip():
            lines.append("")
            continue
        line = ""
        for part in re.split(r"(\s+)", para):
            if not part:
                continue
            if _vislen(line + part) <= width:
                line += part
                continue
            if line.strip():
                lines.append(line.rstrip())
            line = part.lstrip()
            while _vislen(line) > width:
                acc = ""
                i = 0
                while i < len(line):
                    if line[i] == "\x1b":
                        m = re.match(r"\x1b\[[0-9;]*m", line[i:])
                        if m:
                            acc += m.group(0)
                            i += len(m.group(0))
                            continue
                    if _vislen(acc + line[i]) > width:
                        break
                    acc += line[i]
                    i += 1
                if not acc:
                    acc = line[:1]
                    i = 1
                lines.append(acc)
                line = line[i:]
        if line.strip() or line == "":
            if line.strip():
                lines.append(line.rstrip())
    return lines or [""]


def _wrap_lines(text: str, width: int, markup: bool = False) -> list[str]:
    return _wrap_vis(_apply_markup(_strip_html(text), markup), width)


def _when(ts: Any) -> str:
    try:
        value = int(ts)
    except (TypeError, ValueError):
        return ""
    return datetime.fromtimestamp(value, tz=timezone.utc).astimezone().strftime("%d %b %y  %H:%M")


def _as_list(value: Any) -> list:
    return value if isinstance(value, list) else []


def _as_dict(value: Any) -> dict:
    return value if isinstance(value, dict) else {}


def _names(payload: dict) -> tuple[dict, dict]:
    profiles = {}
    for p in _as_list(payload.get("profiles")):
        if isinstance(p, dict) and p.get("id") is not None:
            profiles[int(p["id"])] = (
                ((p.get("first_name") or "") + " " + (p.get("last_name") or "")).strip()
                or p.get("screen_name")
                or ("id" + str(p["id"]))
            )
    groups = {}
    for g in _as_list(payload.get("groups")):
        if isinstance(g, dict) and g.get("id") is not None:
            groups[int(g["id"])] = g.get("name") or ("club" + str(g["id"]))
    return profiles, groups


def _who(oid: Any, profiles: dict, groups: dict) -> str:
    try:
        n = int(oid)
    except (TypeError, ValueError):
        return "?"
    if n < 0:
        return groups.get(-n, "club" + str(-n))
    return profiles.get(n, "id" + str(n))


def _attach_note(item: dict) -> str:
    kinds = []
    for a in _as_list(item.get("attachments") or []):
        if isinstance(a, dict):
            kinds.append(str(a.get("type") or "file"))
    return ("[" + ", ".join(kinds) + "]") if kinds else ""


def normalize_posts(payload: dict) -> list[dict]:
    profiles, groups = _names(payload)
    out = []
    for item in _as_list(payload.get("items")):
        if not isinstance(item, dict):
            continue
        if item.get("type") and item.get("type") not in ("post",):
            continue
        oid = item.get("owner_id", item.get("source_id", item.get("from_id")))
        fid = item.get("from_id", oid)
        pid = item.get("id") or item.get("post_id") or 0
        try:
            oid_i = int(oid)
            pid_i = int(pid)
            fid_i = int(fid)
        except (TypeError, ValueError):
            continue
        author = _who(fid, profiles, groups)
        try:
            if oid is not None and fid is not None and int(oid) != int(fid):
                author += " -> " + _who(oid, profiles, groups)
        except (TypeError, ValueError):
            pass
        text = _strip_html(str(item.get("text") or ""))
        extra = []
        for orig in _as_list(item.get("copy_history") or []):
            if not isinstance(orig, dict):
                continue
            ooid = orig.get("owner_id", orig.get("from_id"))
            extra.append("repost " + _who(ooid, profiles, groups))
            extra.append(_strip_html(str(orig.get("text") or "")))
        att = _attach_note(item)
        if att:
            extra.append(att)
        if extra:
            text = (text + "\n\n" + "\n".join(extra)).strip()
        if not text:
            text = "(no text)"
        likes = _as_dict(item.get("likes")).get("count") or 0
        comments = _as_dict(item.get("comments")).get("count") or 0
        out.append({
            "owner_id": oid_i,
            "post_id": pid_i,
            "author": author,
            "date": _when(item.get("date")),
            "text": text,
            "likes": likes,
            "comments": comments,
            "profile_id": fid_i if fid_i > 0 else (oid_i if oid_i > 0 else None),
        })
    return out


def normalize_comments(payload: dict) -> list[dict]:
    profiles, groups = _names(payload)
    out = []
    for item in _as_list(payload.get("items")):
        if not isinstance(item, dict):
            continue
        text = _strip_html(str(item.get("text") or "")) or "(no text)"
        att = _attach_note(item)
        if att:
            text += "\n" + att
        out.append({
            "author": _who(item.get("from_id"), profiles, groups),
            "date": _when(item.get("date")),
            "text": text,
            "likes": _as_dict(item.get("likes")).get("count") or 0,
            "profile_id": int(item["from_id"]) if item.get("from_id") and int(item["from_id"]) > 0 else None,
        })
    return out


def _as_post_card(p: dict) -> dict:
    return {
        "author": p.get("author") or "",
        "date": p.get("date") or "",
        "meta": "wall%s_%s   +%s  c:%s" % (p.get("owner_id"), p.get("post_id"), p.get("likes") or 0, p.get("comments") or 0),
        "text": p.get("text") or "",
        "owner_id": p.get("owner_id"),
        "post_id": p.get("post_id"),
        "comments": p.get("comments"),
        "profile_id": p.get("profile_id"),
    }


class LineIO:
    def __init__(self, sock: Optional[socket.socket] = None, stdio: bool = False, encoding: str = "utf-8"):
        self.sock = sock
        self.stdio = stdio
        self.encoding = encoding
        self._buf = bytearray()
        self.alive = True
        self.cols = 80
        self.rows = 24
        self.telnet = False
        self.tag = "conn"
        self.peer = "?"
        self.phase = "-"

    def send_raw(self, data: bytes) -> None:
        if not data:
            return
        if self.stdio:
            sys.stdout.buffer.write(data)
            sys.stdout.buffer.flush()
            return
        assert self.sock is not None
        if self.telnet:
            data = data.replace(bytes([IAC]), bytes([IAC, IAC]))
        self.sock.sendall(data)

    def send(self, text: str) -> None:
        data = text.replace("\n", "\r\n").encode(self.encoding, "replace")
        self.send_raw(data)

    def go_ahead(self) -> None:
        if self.stdio or self.sock is None or not self.telnet:
            return
        try:
            self.sock.sendall(bytes([IAC, GA]))
        except OSError:
            self.alive = False

    def cls(self) -> None:
        if self.telnet:
            self.send_raw(b"\x1b[2J\x1b[H")
        else:
            self.send_raw(b"\r\n" * 3)

    def drain_until_quiet(self, quiet: float = 0.3, max_wait: float = 2.0) -> None:
        deadline = time.time() + max_wait
        last = time.time()
        while self.alive and time.time() < deadline:
            got = self.read_key(timeout=0.05)
            if got is None:
                if not self.alive:
                    return
                if time.time() - last >= quiet:
                    return
                continue
            last = time.time()

    def _offer_telnet(self) -> None:
        if self.stdio or self.sock is None:
            return

        self.telnet = True

        pkt = bytes([
            IAC, WILL, ECHO,
            IAC, WILL, SGA,
            IAC, DO, SGA,
            IAC, WILL, BINARY,
            IAC, DO, BINARY,
            IAC, DO, NAWS,
        ])

        self.sock.sendall(pkt)

    def negotiate(self) -> None:
        if self.stdio or self.sock is None:
            return
        self.phase = "negotiate"
        deadline = time.time() + 0.2
        while self.alive and time.time() < deadline:
            ch = self._recv_plain(max(0.01, deadline - time.time()))
            if ch is None:
                continue
            if ch == IAC:
                cmd = self._recv_plain(0.2)
                if cmd is None or cmd not in (WILL, WONT, DO, DONT, SB, GA, 241):
                    if cmd is not None:
                        self._buf.insert(0, cmd)
                    self._buf.insert(0, IAC)
                    return
                self.telnet = True
                self._buf.insert(0, cmd)
                self._handle_iac()
                extra = time.time() + 0.15
                while self.alive and time.time() < extra:
                    nxt = self._recv_plain(max(0.01, extra - time.time()))
                    if nxt is None:
                        break
                    if nxt == IAC:
                        self._handle_iac()
                    elif nxt in (0, 10, 13):
                        continue
                    else:
                        self._buf.insert(0, nxt)
                        break
                self._offer_telnet()
                return
            if ch in (0, 10, 13):
                continue
            self._buf.insert(0, ch)
            return

    def hayes_wait(self) -> None:
        if self.stdio or self.telnet:
            return
        self.phase = "modem"
        self.block()
        buf = bytearray()
        saw_at = False
        last_at = time.time()

        def reply(msg: bytes) -> None:
            try:
                assert self.sock is not None
                self.sock.sendall(msg)

            except OSError:
                self.alive = False

        def wipe() -> None:
            reply(b"\r\nCONNECT 9600\r\n\x0c" + b"\r\n" * 25)

        while self.alive:
            wait = 0.2
            ch = self.read_byte(timeout=wait)
            now = time.time()
            if ch is None:
                if not self.alive:
                    return
                if saw_at and now - last_at >= 1.6:
                    if buf:
                        self._buf.extend(buf)
                        buf.clear()
                    wipe()
                    return
                continue
            if ch in (13, 10):
                self._eat_eol()
                line = buf.decode("ascii", "replace").strip()
                buf.clear()

                if not line:
                    continue

                up = line.upper().replace(" ", "")
                if up.startswith("AT"):
                    saw_at = True
                    last_at = now
                    if up.startswith("ATD") or up.startswith("ATA") or up == "ATO":
                        reply(b"\r\nOK\r\n")
                        wipe()
                        return
                    reply(b"\r\nOK\r\n")
                    continue
                for b in line.encode("ascii", "replace"):
                    self._buf.append(b)
                wipe()
                return
            if ch in (8, 127):
                if buf:
                    buf.pop()
                continue
            if ch >= 32 and len(buf) < 120:
                buf.append(ch)

    def close(self) -> None:
        self.alive = False
        if self.sock is not None:
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                self.sock.close()
            except OSError:
                pass

    def decode_line(self, raw: bytes) -> str:
        for enc in (self.encoding, "utf-8", "cp1251", "cp866"):
            try:
                return raw.decode(enc)
            except UnicodeDecodeError:
                continue
        return raw.decode(self.encoding, "replace")

    def _apply_naws(self, payload: bytes) -> None:
        if len(payload) >= 4:
            self.cols = max(40, min(200, (payload[0] << 8) | payload[1]))
            self.rows = max(12, min(80, (payload[2] << 8) | payload[3]))

    def _handle_iac(self) -> Optional[int]:
        cmd = self._eat_raw()
        if cmd is None:
            return None
        if cmd in (WILL, WONT, DO, DONT):
            opt = self._eat_raw()
            if opt is None:
                return None
            self._reply_option(cmd, opt)
            return -1
        if cmd == SB:
            opt = self._eat_raw()
            chunk = bytearray()
            while True:
                x = self._eat_raw()
                if x is None:
                    return None
                if x == IAC:
                    y = self._eat_raw()
                    if y == SE:
                        break
                    if y == IAC:
                        chunk.append(IAC)
                    continue
                chunk.append(x)
            if opt == NAWS:
                self._apply_naws(bytes(chunk))
            return -1
        if cmd == IAC:
            return IAC
        return -1

    def _recv_plain(self, timeout: Optional[float] = None) -> Optional[int]:
        if self._buf:
            return self._buf.pop(0)
        if self.stdio or self.sock is None:
            return None
        old = self.sock.gettimeout()
        try:
            self.sock.settimeout(timeout)
            chunk = self.sock.recv(4096)
        except socket.timeout:
            return None
        except OSError:
            self.alive = False
            return None
        finally:
            try:
                self.sock.settimeout(old)
            except OSError:
                pass
        if not chunk:
            self.alive = False
            return None
        self._buf.extend(chunk[1:])
        return chunk[0]

    def _eat_raw(self) -> Optional[int]:
        return self._recv_plain(0.4)

    def _eat_eol(self) -> None:
        for _ in range(6):
            nxt = self.read_byte(timeout=0.03)
            if nxt in (0, 10, 13):
                continue
            if nxt is not None:
                self._buf.insert(0, nxt)
            return

    def read_byte(self, timeout: Optional[float] = None) -> Optional[int]:
        if self.stdio:
            return self._stdio_byte()
        assert self.sock is not None
        while self.alive:
            ch = self._recv_plain(timeout)
            if ch is None:
                return None
            if ch == IAC and self.telnet:
                got = self._handle_iac()
                if got == -1:
                    continue
                return got
            return ch
        return None

    def _stdio_byte(self) -> Optional[int]:
        try:
            if os.name == "nt":
                import msvcrt
                ch = msvcrt.getwch()
                if ch in ("\x00", "\xe0"):
                    extra = msvcrt.getwch()
                    return {"H": 1000, "P": 1001, "K": 1002, "M": 1003}.get(extra, 0)
                return ord(ch)
            import tty
            import termios
            fd = sys.stdin.fileno()
            old = termios.tcgetattr(fd)
            try:
                tty.setraw(fd)
                data = os.read(fd, 8)
            finally:
                termios.tcsetattr(fd, termios.TCSADRAIN, old)
            if not data:
                return None
            self._buf.extend(data[1:])
            return data[0]
        except (KeyboardInterrupt, EOFError, OSError):
            return None

    def pending(self) -> bool:
        return bool(self._buf)

    def read_key(self, timeout: Optional[float] = None) -> Optional[str]:
        key = self._read_key(timeout)

        return key

    def _read_key(self, timeout: Optional[float] = None) -> Optional[str]:
        ch = self.read_byte(timeout=timeout)
        if ch is None:
            return None
        if ch == 1000:
            return "up"
        if ch == 1001:
            return "down"
        if ch == 1002:
            return "left"
        if ch == 1003:
            return "right"
        if ch == 3:
            self.alive = False
            return None
        if ch in (8, 127):
            return "backspace"
        while ch == 0:
            ch = self.read_byte(timeout=0.02)
            if ch is None:
                return "enter"
        if ch in (13, 10):
            self._eat_eol()
            return "enter"
        if ch == 27:
            nxt = self.read_byte(timeout=0.25)
            if nxt is None:
                return "esc"
            if nxt == 91:
                return self._read_csi()
            if nxt == 79:
                fin = self.read_byte(timeout=0.25)
                if fin == 65:
                    return "up"
                if fin == 66:
                    return "down"
                if fin == 67:
                    return "right"
                if fin == 68:
                    return "left"
            return "esc"

        if 32 <= ch < 128:
            return chr(ch)

        raw = bytearray([ch])
        while True:
            nxt = self.read_byte(timeout=0.02)
            if nxt is None:
                break
            if nxt < 32 or nxt in (IAC,):
                self._buf.insert(0, nxt)
                break
            raw.append(nxt)
            if len(raw) >= 4:
                break
        s = self.decode_line(bytes(raw))
        return s if s else " "

    def _read_csi(self) -> str:
        params = bytearray()
        while True:
            b = self.read_byte(timeout=0.25)
            if b is None:
                return "esc"
            if 0x30 <= b <= 0x3F:
                params.append(b)
                continue
            if 0x20 <= b <= 0x2F:
                continue
            if b == 65:
                return "up"
            if b == 66:
                return "down"
            if b == 67:
                return "right"
            if b == 68:
                return "left"
            if b == 126:
                if params[:1] == b"5":
                    return "pgup"
                if params[:1] == b"6":
                    return "pgdn"
            return "esc"

    def block(self) -> None:
        if self.sock is not None:
            try:
                self.sock.settimeout(None)
            except OSError:
                pass

    def read_isolated(self, allowed: set[str]) -> Optional[str]:
        self.block()
        while self.alive:
            key = self.read_key()
            if key is None:
                if not self.alive:
                    return None
                continue
            if key not in allowed:
                continue
            burst = False
            while True:
                nxt = self.read_key(timeout=0.18)
                if nxt is None:
                    break
                if nxt in ("enter", "esc"):
                    continue
                burst = True
            if burst:
                continue
            return key
        return None

    def readline(self, hide: bool = False, echo: bool = True) -> Optional[str]:
        if self.stdio:
            try:
                if hide and sys.stdin.isatty():
                    return getpass.getpass("")
                line = sys.stdin.buffer.readline()
            except (KeyboardInterrupt, EOFError):
                return None
            if not line:
                return None
            return self.decode_line(line).rstrip("\r\n")

        self.block()
        raw = bytearray()
        while self.alive:
            ch = self.read_byte()
            if ch is None:
                if not self.alive:
                    return None
                continue
            if ch == 27:
                nxt = self.read_byte(timeout=0.25)
                if nxt == 91:
                    self._read_csi()
                elif nxt == 79:
                    self.read_byte(timeout=0.25)
                raw.clear()
                continue
            if ch in (8, 127):
                if raw:
                    if self.encoding.lower() in ("utf-8", "utf8"):
                        while raw and (raw[-1] & 0xC0) == 0x80:
                            raw.pop()
                        if raw:
                            raw.pop()
                    else:
                        raw.pop()
                    if echo and not hide:
                        self.send_raw(b"\b \b")
                continue
            if ch in (13, 10):
                self._eat_eol()
                if echo and not hide:
                    self.send_raw(b"\r\n")
                break
            if ch == 3:
                return None
            if ch == 4:
                if not raw:
                    return None
                break
            if ch < 32:
                continue
            if len(raw) >= 80:
                raw.clear()
                continue
            raw.append(ch)
            if echo and not hide:
                self.send_raw(bytes([ch]))
        return self.decode_line(bytes(raw))

    def _reply_option(self, cmd: int, opt: int) -> None:
        if self.sock is None:
            return
        if cmd == DO and opt in (ECHO, SGA, BINARY):
            return
        if cmd == WILL and opt in (SGA, BINARY, NAWS):
            return
        if cmd == WILL and opt == ECHO:
            self.sock.sendall(bytes([IAC, DONT, ECHO]))
            return
        if cmd == DO:
            self.sock.sendall(bytes([IAC, WONT, opt]))
        elif cmd == WILL:
            self.sock.sendall(bytes([IAC, DONT, opt]))


def _vislen(text: str) -> int:
    return len(re.sub(r"\x1b\[[0-9;]*m", "", text or ""))


def _vis_pad(text: str, width: int) -> str:
    n = _vislen(text)
    if n >= width:
        return text
    return text + (" " * (width - n))


def _vis_center(text: str, width: int) -> str:
    n = _vislen(text)
    if n >= width:
        return text
    left = (width - n) // 2
    right = width - n - left
    return (" " * left) + text + (" " * right)


def _hline(cols: int, left: str, right: str) -> str:
    return left + H * max(0, cols - 2) + right


def _vline(text: str, cols: int) -> str:
    inner = max(0, cols - 2)
    return V + _vis_pad(text or "", inner) + V


class Session:
    def __init__(self, io: LineIO, default_instance: Optional[str] = None, skip_detect: bool = False):
        self.io = io
        self.default_instance = default_instance
        self.skip_detect = skip_detect
        self.api: Optional[OvkApi] = None
        self._posts: list[dict] = []
        self._next_from = ""
        self._global = False
        self.ansi = True

    def sty(self, text: str, *attrs: str) -> str:
        if not self.ansi or not text:
            return text
        codes = {
            "bold": "1",
            "dim": "2",
            "italic": "3",
            "underline": "4",
            "rev": "7",
            "strike": "9",
            "black": "30",
            "red": "31",
            "green": "32",
            "yellow": "33",
            "blue": "34",
            "magenta": "35",
            "cyan": "36",
            "white": "37",
        }
        seq = ";".join(codes[a] for a in attrs if a in codes)
        if not seq:
            return text
        return "\x1b[%sm%s\x1b[0m" % (seq, text)

    def write(self, text: str = "") -> None:
        self.io.send(text if text.endswith("\n") or text == "" else text + "\n")

    def paint(self, lines: list[str]) -> None:
        body = "\n".join(line + "\x1b[K" for line in lines)
        self.io.send_raw(b"\x1b[?25l\x1b[H")
        self.io.send(body + "\n\x1b[J")

    def prompt(self, label: str, hide: bool = False) -> Optional[str]:
        self.io.send(label)
        return self.io.readline(hide=hide)

    def width(self) -> int:
        return max(40, self.io.cols - 1)

    def rule(self) -> str:
        return "-" * self.width()

    def write_heading(self, title: str, right: str = "") -> None:
        if right:
            gap = max(1, self.width() - _vislen(title) - _vislen(right))
            self.write(title + (" " * gap) + right)
        else:
            self.write(title)
        self.write(self.rule())
        self.write()

    def bar_top(self) -> str:
        return _hline(self.width(), TL, TR)

    def bar_mid(self) -> str:
        return _hline(self.width(), ML, MR)

    def bar_bot(self) -> str:
        return _hline(self.width(), BL, BR)

    def bar_row(self, text: str = "") -> str:
        return _vline(text, self.width())

    def compose(self, heading: str) -> Optional[str]:
        self.write()
        self.write_heading(self.sty(heading, "bold"))
        self.write(self.sty("  '.' ends   empty first line aborts", "dim"))
        lines: list[str] = []
        while True:
            chunk = self.prompt("  ] ")
            if chunk is None:
                return None
            if chunk == ".":
                break
            if chunk == "" and not lines:
                return ""
            if chunk == "":
                break
            lines.append(chunk)
        return "\n".join(lines).strip()

    def detect_encoding(self) -> None:
        if self.skip_detect or self.io.stdio:
            return
        self.io.phase = "enc-draw"
        self.io.block()
        rows = (
            ("utf-8", b"  1.    UTF-8   PuTTY\r\n      "),
            ("cp866", b"  2.   DOS OEM\r\n      "),
            ("cp1251", b"  3.    Windows\r\n      "),
        )
        self.io.send_raw(b"\r\n\r\nLainTel -- encoding check\r\n\r\n")
        self.io.send_raw(b"Which line is readable Russian?\r\n\r\n")
        for enc, prefix in rows:
            try:
                sample = SAMPLE.encode(enc)
            except LookupError:
                continue
            self.io.send_raw(prefix + sample + b"\r\n")
        self.io.send_raw(b"\r\n  1 / 2 / 3  -- hit that key\r\n")
        self.io.send_raw(b"  Your choice: ")
        self.io.phase = "enc-drain"
        self.io.drain_until_quiet(quiet=0.4, max_wait=3.0)
        self.io._buf.clear()
        mapping = {"1": "utf-8", "2": "cp866", "3": "cp1251"}
        key = None
        at = []
        self.io.phase = "enc-wait"
        self.io.block()
        while self.io.alive:
            got = self.io.read_key()
            if got is None:
                if not self.io.alive:
                    return
                continue
            if got == "enter":
                raw = "".join(at)
                at = []
                if raw.upper().replace(" ", "").startswith("AT"):
                    try:
                        self.io.sock.sendall(b"\r\nOK\r\n") if self.io.sock else None
                    except OSError:
                        self.io.alive = False
                continue
            if len(got) != 1:
                continue
            maybe = ("".join(at) + got).upper().replace(" ", "")
            if maybe.startswith("A") or (at and "".join(at).upper().lstrip().startswith("AT")):
                at.append(got)
                continue
            if at:
                at.append(got)
                continue
            if got in mapping:
                extra = False
                while True:
                    nxt = self.io.read_key(timeout=0.12)
                    if nxt is None:
                        break
                    if nxt in ("enter", "esc"):
                        continue
                    extra = True
                    break
                if extra:
                    continue
                key = got
                break
        if key:
            self.io.encoding = mapping[key]
            self.io.send_raw(key.encode("ascii") + b"\r\n")
        else:
            self.io.encoding = "cp866" if not self.io.telnet else "utf-8"
        self.write("  codepage: " + self.io.encoding)
        self.io.drain_until_quiet(quiet=0.2, max_wait=1.0)
        self.io.block()

    def draw_menu(self) -> None:
        w = self.width()
        node = self.api.instance if self.api else "offline"
        if self.api and self.api.access_token:
            user = (self.api.user_name or "user") + "  #" + str(self.api.user_id)
        else:
            user = "guest"
        title = _vis_center(self.sty("LainTel", "bold"), w - 2)
        items = [
            ("1", "Node"),
            ("2", "Login"),
            ("3", "Newsfeed"),
            ("4", "Global"),
            ("5", "Post"),
            ("7", "Mail"),
            ("8", "Friends"),
            ("6", "Logoff"),
            ("C", "Codepage"),
            ("A", "ANSI  " + ("ON" if self.ansi else "OFF")),
            ("G", "Goodbye"),
        ]
        self.io.cls()
        self.write(self.bar_top())
        self.write(_vline(title, w))
        self.write(self.bar_mid())
        self.write(self.bar_row("  " + self.sty("Node", "bold") + " : " + node))
        self.write(self.bar_row("  " + self.sty("User", "bold") + " : " + user))
        self.write(self.bar_row("  " + self.sty("Page", "bold") + " : %s   %sx%s" % (self.io.encoding.upper(), self.io.cols, self.io.rows)))
        self.write(self.bar_mid())
        self.write(self.bar_row())
        for num, name in items:
            line = "    (" + self.sty(num, "bold", "yellow") + ")  " + name
            self.write(self.bar_row(line))
        self.write(self.bar_row())
        self.write(self.bar_bot())
        self.io.send("  " + self.sty("Your choice:", "bold") + " ")
        self.io.go_ahead()

    def ensure_instance(self) -> bool:
        if self.api:
            return True
        hint = self.default_instance or "https://lainlife.org"
        self.write()
        self.write("  Node URL  (blank = %s)" % hint)
        url = self.prompt("  : ")
        if url is None:
            return False
        url = url.strip() or hint
        return self.set_instance(url)

    def set_instance(self, url: str) -> bool:
        self.write("  connecting...")
        try:
            api = OvkApi(url)
            ver = api.probe()
        except OvkApiError as exc:
            self.write("  refused: %s" % exc)
            return False
        self.api = api
        self.write("  connected  %s" % api.instance)
        self.write("  %s" % ver)
        return True

    def do_node(self) -> None:
        hint = (self.api.instance if self.api else None) or self.default_instance or "https://lainlife.org"
        self.write()
        self.write("  Current node: %s" % (self.api.instance if self.api else "none"))
        url = self.prompt("  URL: ")
        if url is None:
            return
        url = url.strip()
        if not url:
            if self.api:
                return
            url = hint
        if self.api:
            self.api.logout()
        self.set_instance(url)
        self.prompt("  [Enter] ")

    def do_login(self) -> None:
        if not self.ensure_instance():
            return
        assert self.api is not None
        self.write()
        user = self.prompt("  E-mail: ")
        if user is None:
            return
        user = user.strip()
        if not user:
            self.write("  aborted.")
            return
        pw = self.prompt("  Password: ", hide=True)
        if pw is None:
            return
        self.write()
        code = None
        while True:
            try:
                self.api.login(user, pw, code=code)
                break
            except OvkApiError as exc:
                if str(exc) == "need_validation" or exc.payload.get("error") == "need_validation":
                    code = self.prompt("  2FA: ")
                    if not code:
                        self.write("  aborted.")
                        return
                    continue
                self.write("  login failed: %s" % exc)
                self.prompt("  [Enter] ")
                return
        self.write("\n  hello, %s  (#%s)" % (self.api.user_name or user, self.api.user_id))
        self.prompt("  [Enter] ")

    def require_auth(self) -> bool:
        if not self.ensure_instance():
            return False
        assert self.api is not None
        if not self.api.access_token:
            self.write("  not logged in.")
            self.prompt("  [Enter] ")
            return False
        return True

    def _fetch_page(self, start_from: str, global_feed: bool) -> tuple[list[dict], str]:
        assert self.api is not None
        payload = self.api.newsfeed(count=15, start_from=start_from, global_feed=global_feed)
        posts = normalize_posts(payload)
        nxt = str(payload.get("next_from") or "")
        return posts, nxt

    def _paint_card(self, title: str, idx: int, total: str, who: str, when: str, meta: str, body: str, body_off: int, footer: str) -> tuple[int, bool, bool]:
        cols = self.width()
        rows = self.io.rows
        extra_head = 0
        if who:
            extra_head += 1
        if when:
            extra_head += 1
        if meta:
            extra_head += 1
        if extra_head:
            extra_head += 1
        body_budget = max(3, rows - 3 - extra_head - 2)
        wrapped = _wrap_lines(body, cols, self.ansi)
        page = wrapped[body_off:body_off + body_budget]
        more_after = body_off + body_budget < len(wrapped)
        more_before = body_off > 0
        extra = []
        if more_before:
            extra.append(self.sty("up", "bold", "yellow") + " more")
        if more_after:
            extra.append(self.sty("dn", "bold", "yellow") + " more")
        if extra:
            footer = footer + "   " + "  ".join(extra)
        self.io.cls()
        self.write_heading(self.sty(title, "bold"), self.sty("%s/%s" % (idx + 1, total), "dim"))
        if who:
            self.write(self.sty(who, "bold", "cyan"))
        if when:
            self.write(self.sty(when, "dim"))
        if meta:
            self.write(self.sty(meta, "dim"))
        if who or when or meta:
            self.write()
        for line in page:
            self.write(line)
        for _ in range(max(0, body_budget - len(page))):
            self.write()
        self.write(self.rule())
        self.write(footer)
        return body_budget, more_before, more_after

    def _reader(self, title: str, cards: list[dict], load_more=None, comments_of=None, write_of=None, open_of=None, profile_of=None) -> None:
        while self.io.alive and not cards:
            self.io.cls()
            self.write_heading(self.sty("empty", "dim"))
            hint = self.sty("Q", "bold", "yellow") + " back"
            if write_of:
                hint = self.sty("W", "bold", "yellow") + " write   " + hint
            self.write(hint)
            key = self.io.read_key()
            if key is None or key in ("q", "Q", "esc"):
                return
            if key in ("w", "W", "r", "R") and write_of:
                write_of({})
        if not cards:
            return
        i = 0
        body_off = 0
        while self.io.alive:
            if not cards:
                return
            if i >= len(cards):
                i = len(cards) - 1
                body_off = 0
            card = cards[i]
            total = str(len(cards)) + ("+" if load_more else "")
            bits = [self.sty("up/dn", "dim")]
            if open_of:
                bits.append(self.sty("Enter", "bold", "yellow") + " open")
            if comments_of:
                bits.append(self.sty("C", "bold", "yellow") + " comments")
            if write_of:
                bits.append(self.sty("W", "bold", "yellow") + " write")
            if profile_of:
                bits.append(self.sty("I", "bold", "yellow") + " profile")
            bits.append(self.sty("Q", "bold", "yellow") + " back")
            budget, more_before, more_after = self._paint_card(
                title,
                i,
                total,
                card.get("author") or "",
                card.get("date") or "",
                card.get("meta") or "",
                card.get("text") or "",
                body_off,
                "  ".join(bits),
            )
            key = self.io.read_key()
            if key is None or key in ("q", "Q", "esc"):
                return
            if key in ("c", "C") and comments_of:
                comments_of(card)
                body_off = 0
                continue
            if key == "enter" and open_of:
                open_of(card)
                body_off = 0
                continue
            if key in ("w", "W", "r", "R") and write_of:
                write_of(card)
                body_off = 0
                continue
            if key in ("i", "I") and profile_of:
                profile_of(card)
                body_off = 0
                continue
            if key in ("down", "right", "n", "N", "j", "J", " "):
                if more_after:
                    body_off += budget
                    continue
                if i + 1 < len(cards):
                    i += 1
                    body_off = 0
                elif load_more:
                    more = load_more()
                    if more:
                        cards.extend(more)
                        i += 1
                        body_off = 0
                continue
            if key in ("up", "left", "p", "P", "k", "K"):
                if more_before:
                    body_off = max(0, body_off - budget)
                    continue
                if i > 0:
                    i -= 1
                    body_off = 0
                continue
            if key in ("f", "F"):
                if more_after:
                    body_off += budget
                continue

    def do_feed(self, global_feed: bool) -> None:
        if not self.require_auth():
            return
        assert self.api is not None
        self._global = global_feed
        try:
            posts, nxt = self._fetch_page("", global_feed)
        except OvkApiError as exc:
            self.write("  %s" % exc)
            self.prompt("  [Enter] ")
            return
        self._posts = posts
        self._next_from = nxt
        title = "GLOBAL" if global_feed else "NEWSFEED"

        def load_more():
            if not self._next_from:
                return []
            try:
                extra, nxt2 = self._fetch_page(self._next_from, global_feed)
            except OvkApiError:
                return []
            self._next_from = nxt2
            return [_as_post_card(p) for p in extra]

        cards = [_as_post_card(p) for p in posts]
        self._reader(
            title,
            cards,
            load_more=load_more,
            comments_of=self.do_comments,
            write_of=self.do_write_comment,
            profile_of=self.do_profile,
        )

    def _comment_cards(self, post: dict) -> list[dict]:
        assert self.api is not None
        payload = self.api.wall_comments(int(post["owner_id"]), int(post["post_id"]))
        comments = normalize_comments(payload)
        total = int(payload.get("count") or len(comments))
        return [
            {
                "author": c["author"],
                "date": c["date"],
                "meta": "comment   +%s   of %s" % (c["likes"], total),
                "text": c["text"],
                "profile_id": c.get("profile_id"),
            }
            for c in comments
        ]

    def do_write_comment(self, card: dict) -> None:
        if not self.api:
            return
        owner = card.get("owner_id")
        post_id = card.get("post_id")
        if owner is None or post_id is None:
            return
        message = self.compose("Write comment")
        if message is None:
            return
        if not message:
            self.write("  aborted.")
            self.prompt("  [Enter] ")
            return
        try:
            cid = self.api.wall_create_comment(int(owner), int(post_id), message)
        except OvkApiError as exc:
            self.write("  %s" % exc)
            self.prompt("  [Enter] ")
            return
        self.write("  comment #%s" % cid)
        self.prompt("  [Enter] ")

    def do_comments(self, card: dict) -> None:
        if not self.api:
            return
        try:
            cards = self._comment_cards(card)
        except OvkApiError as exc:
            self.io.cls()
            self.write(str(exc))
            self.io.read_key()
            return

        def write(_ignored: dict) -> None:
            self.do_write_comment(card)
            try:
                cards[:] = self._comment_cards(card)
            except OvkApiError:
                return

        self._reader("COMMENTS", cards, write_of=write, profile_of=self.do_profile)

    def do_post(self) -> None:
        if not self.require_auth():
            return
        assert self.api is not None
        message = self.compose("New post")
        if message is None:
            return
        if not message:
            self.write("  aborted.")
            self.prompt("  [Enter] ")
            return
        try:
            post_id = self.api.wall_post(message)
        except OvkApiError as exc:
            self.write("  %s" % exc)
            self.prompt("  [Enter] ")
            return
        self.write("  posted  wall%s_%s" % (self.api.user_id, post_id))
        self.prompt("  [Enter] ")

    def _mail_cards(self, offset: int = 0) -> tuple[list[dict], int]:
        assert self.api is not None
        payload = self.api.messages_conversations(offset=offset, count=15)
        profiles, _groups = _names(payload)
        cards = []
        for it in _as_list(payload.get("items")):
            if not isinstance(it, dict):
                continue
            conv = _as_dict(it.get("conversation"))
            peer = _as_dict(conv.get("peer")).get("id")
            last = _as_dict(it.get("last_message"))
            if peer is None:
                continue
            try:
                peer_id = int(peer)
            except (TypeError, ValueError):
                continue
            text = str(last.get("text") or last.get("body") or "")
            out = int(last.get("out") or 0)
            prefix = "you: " if out else ""
            cards.append({
                "author": _who(peer_id, profiles, {}),
                "date": _when(last.get("date")),
                "meta": "id%s" % peer_id,
                "text": prefix + text if text else "(no text)",
                "peer_id": peer_id,
            })
        return cards, int(payload.get("count") or len(cards))

    def do_mail_new(self, _card: dict = None) -> None:
        if not self.require_auth():
            return
        assert self.api is not None
        who = self.prompt("  user id / nick: ")
        if who is None:
            return
        who = who.strip()
        if not who:
            return
        try:
            peer = self.api.resolve_screen_name(who)
        except OvkApiError as exc:
            self.write("  %s" % exc)
            self.prompt("  [Enter] ")
            return
        if not peer:
            self.write("  user not found.")
            self.prompt("  [Enter] ")
            return
        message = self.compose("New message")
        if not message:
            self.write("  aborted.")
            self.prompt("  [Enter] ")
            return
        try:
            mid = self.api.messages_send(peer, message)
        except OvkApiError as exc:
            self.write("  %s" % exc)
            self.prompt("  [Enter] ")
            return
        self.write("  sent #%s" % mid)
        self.prompt("  [Enter] ")
        self.do_chat({"peer_id": peer, "author": who})

    def do_chat(self, card: dict) -> None:
        if not self.api:
            return
        try:
            peer_id = int(card["peer_id"])
        except (KeyError, TypeError, ValueError):
            return
        name = card.get("author") or ("id%s" % peer_id)
        collected: list[dict] = []
        profiles: dict = {}
        line_start: Optional[int] = None
        exhausted = False

        def pull() -> int:
            nonlocal exhausted
            if exhausted:
                return 0
            payload = self.api.messages_history(peer_id, offset=len(collected), count=30)
            pr, _g = _names(payload)
            profiles.update(pr)
            batch = [m for m in _as_list(payload.get("items")) if isinstance(m, dict)]
            if not batch:
                exhausted = True
                return 0
            collected.extend(batch)
            if len(batch) < 30:
                exhausted = True
            return len(batch)

        try:
            pull()
        except OvkApiError as exc:
            self.io.cls()
            self.write(str(exc))
            self.io.read_key()
            return

        while self.io.alive:
            profiles: dict = {}
            try:
                if not collected:
                    pull()
            except OvkApiError:
                pass
            if self.api.user_id:
                profiles.setdefault(int(self.api.user_id), "you")

            lines: list[str] = []
            for m in reversed(collected):
                from_id = m.get("from_id") or m.get("user_id")
                out = int(m.get("out") or 0)
                if out:
                    who = self.sty("you", "bold", "green")
                else:
                    who = self.sty(_who(from_id, profiles, {}), "bold", "cyan")
                stamp = self.sty(_when(m.get("date")), "dim")
                body = str(m.get("text") or m.get("body") or "")
                wrapped = _wrap_lines(body, self.width() - 2, self.ansi)
                lines.append(stamp + "  " + who)
                for wl in wrapped:
                    lines.append("  " + wl)
                lines.append("")

            rows = self.io.rows
            budget = max(4, rows - 5)
            max_start = max(0, len(lines) - budget)
            if line_start is None:
                start = max_start
            else:
                start = max(0, min(line_start, max_start))
            page = lines[start:start + budget]
            can_older = start > 0 or not exhausted
            can_newer = start < max_start
            footer = (
                self.sty("W", "bold", "yellow") + " write   "
                + self.sty("I", "bold", "yellow") + " profile   "
                + (self.sty("up", "bold", "yellow") + " older   " if can_older else "")
                + (self.sty("dn", "bold", "yellow") + " newer   " if can_newer else "")
                + self.sty("Q", "bold", "yellow") + " back"
            )
            self.io.cls()
            self.write_heading(self.sty("MAIL", "bold") + "  " + name)
            for line in page:
                self.write(line)
            for _ in range(max(0, budget - len(page))):
                self.write()
            self.write(self.rule())
            self.write(footer)
            key = self.io.read_key()
            if key is None or key in ("q", "Q", "esc"):
                return
            if key in ("i", "I"):
                self.do_profile({"profile_id": peer_id, "peer_id": peer_id, "author": name})
                continue
            if key in ("w", "W", "r", "R"):
                msg = self.compose("Message")
                if msg:
                    try:
                        self.api.messages_send(peer_id, msg)
                        collected.clear()
                        exhausted = False
                        line_start = None
                        pull()
                    except OvkApiError as exc:
                        self.write("  %s" % exc)
                        self.prompt("  [Enter] ")
                continue
            if key in ("up", "p", "P", "k", "K"):
                if start > 0:
                    line_start = max(0, start - budget)
                else:
                    added = 0
                    try:
                        added = pull()
                    except OvkApiError as exc:
                        self.write("  %s" % exc)
                        self.prompt("  [Enter] ")
                    if added:
                        line_start = 0
                continue
            if key in ("down", "n", "N", "j", "J"):
                if start + budget >= len(lines):
                    line_start = None
                else:
                    line_start = start + budget

    def do_mail(self) -> None:
        if not self.require_auth():
            return
        assert self.api is not None
        try:
            cards, total = self._mail_cards(0)
        except OvkApiError as exc:
            self.write("  %s" % exc)
            self.prompt("  [Enter] ")
            return
        mail_off = [0]

        def load_more():
            mail_off[0] += 15
            try:
                extra, _t = self._mail_cards(mail_off[0])
            except OvkApiError:
                return []
            return extra

        self._reader(
            "MAIL",
            cards,
            load_more=load_more,
            open_of=self.do_chat,
            write_of=self.do_mail_new,
            profile_of=self.do_profile,
        )

    def _uid(self, card: dict) -> Optional[int]:
        for key in ("profile_id", "peer_id", "user_id"):
            val = card.get(key)
            try:
                n = int(val)
            except (TypeError, ValueError):
                continue
            if n > 0:
                return n
        return None

    def _friend_label(self, status: int) -> str:
        return "yes" if status == 3 else "no"

    def _kv(self, label: str, value: str) -> str:
        return self.sty(label, "dim") + " " + value

    def _pick_list(self, title: str, items: list[dict], load_more=None, on_open=None, extra=None, extra_hint: str = "") -> None:
        extra = extra or {}
        if not items:
            self.io.cls()
            self.write_heading(self.sty(title, "bold"))
            self.write(self.sty("empty", "dim"))
            self.write()
            self.write(self.rule())
            self.write(self.sty("Q", "bold", "yellow") + " back")
            self.io.read_key()
            return
        hi = 0
        top = 0
        more = True if load_more else False

        def row_text(idx: int, selected: bool) -> str:
            it = items[idx]
            mark = ">" if selected else " "
            name = (it.get("author") or "")[:22]
            on = (it.get("date") or "")[:8]
            meta = it.get("meta") or ""
            body = " %s %3d  %-22s  %-8s  %s" % (mark, idx + 1, name, on, meta)
            if selected:
                return self.sty(body, "rev")
            return body

        def paint() -> None:
            nonlocal top
            if not items:
                return
            budget = max(5, self.io.rows - 5)
            if hi < top:
                top = hi
            if hi >= top + budget:
                top = hi - budget + 1
            page_n = min(budget, len(items) - top)
            total = str(len(items)) + ("+" if more else "")
            head = self.sty(title, "bold")
            right = self.sty("%s/%s" % (hi + 1, total), "dim")
            gap = max(1, self.width() - _vislen(head) - _vislen(right))
            foot = (
                self.sty("up/dn", "dim") + "   "
                + self.sty("Enter", "bold", "yellow") + " profile   "
                + extra_hint
                + self.sty("Q", "bold", "yellow") + " back"
            )
            lines = [
                head + (" " * gap) + right,
                self.rule(),
            ]
            for n in range(page_n):
                idx = top + n
                lines.append(row_text(idx, idx == hi))
            lines.append(self.rule())
            lines.append(foot)
            self.paint(lines)

        try:
            while self.io.alive:
                if not items:
                    self.io.cls()
                    self.write_heading(self.sty(title, "bold"))
                    self.write(self.sty("empty", "dim"))
                    self.write()
                    self.write(self.rule())
                    self.write(self.sty("Q", "bold", "yellow") + " back")
                    self.io.read_key()
                    return
                paint()
                key = self.io.read_key()
                if key is None or key in ("q", "Q", "esc"):
                    return
                step = 0
                while key is not None:
                    budget = max(5, self.io.rows - 5)
                    if key in ("up", "k", "K", "p", "P"):
                        step -= 1
                    elif key in ("down", "j", "J", "n", "N", " ") and key not in extra:
                        step += 1
                    elif key in ("pgup", "left"):
                        step -= budget
                    elif key in ("pgdn", "right"):
                        step += budget
                    elif key in ("enter", "i", "I", "o", "O") and on_open:
                        hi = max(0, min(hi + step, max(0, len(items) - 1)))
                        on_open(items[hi])
                        step = 0
                        break
                    elif extra and key in extra and items:
                        hi = max(0, min(hi + step, max(0, len(items) - 1)))
                        if extra[key](items[hi]):
                            items.pop(hi)
                            if hi >= len(items):
                                hi = max(0, len(items) - 1)
                        step = 0
                        break
                    else:
                        break
                    if self.io.pending():
                        key = self.io.read_key()
                        continue
                    break
                if step:
                    want = hi + step
                    while want >= len(items) and more and load_more:
                        extra_rows = load_more()
                        if extra_rows:
                            items.extend(extra_rows)
                        else:
                            more = False
                    hi = max(0, min(want, len(items) - 1))
        finally:
            self.io.send_raw(b"\x1b[?25h")

    def do_profile(self, card: dict) -> None:
        if not self.require_auth():
            return
        assert self.api is not None
        uid = self._uid(card)
        if not uid:
            self.write("  no profile")
            self.prompt("  [Enter] ")
            return
        while self.io.alive:
            try:
                users = self.api.users_get(str(uid))
            except OvkApiError as exc:
                self.write("  %s" % exc)
                self.prompt("  [Enter] ")
                return
            if not users:
                self.write("  user not found")
                self.prompt("  [Enter] ")
                return
            u = users[0]
            name = ((u.get("first_name") or "") + " " + (u.get("last_name") or "")).strip() or ("id%s" % uid)
            st = int(u.get("friend_status") or 0)
            mine = self.api.user_id == uid
            city = u.get("city")
            if isinstance(city, dict):
                city = city.get("title") or ""
            counters = _as_dict(u.get("counters"))
            keys = [self.sty("W", "bold", "yellow") + " wall"]
            if not mine:
                keys.append(self.sty("M", "bold", "yellow") + " mail")
                if st == 0:
                    keys.append(self.sty("F", "bold", "yellow") + " add")
                elif st == 2:
                    keys.append(self.sty("F", "bold", "yellow") + " accept")
                elif st == 3:
                    keys.append(self.sty("F", "bold", "yellow") + " unfriend")
            keys.append(self.sty("Q", "bold", "yellow") + " back")
            self.io.cls()
            who = self.sty(name, "bold", "cyan") + self.sty("  #%s" % uid, "dim")
            if u.get("screen_name"):
                who += "  @" + str(u["screen_name"])
            if u.get("deactivated"):
                who += "  " + self.sty(str(u["deactivated"]), "red")
            self.write(self.sty("PROFILE", "bold") + "  " + who)
            self.write(self.rule())
            bits = [
                self._kv("online", self.sty("yes", "bold", "green") if int(u.get("online") or 0) else self.sty("no", "dim")),
            ]
            if not mine:
                bits.append(self._kv("friends", self.sty("yes" if st == 3 else "no", "bold", "green" if st == 3 else "dim")))
                if st == 1:
                    bits.append(self._kv("request", "outgoing"))
                elif st == 2:
                    bits.append(self._kv("request", "incoming"))
            self.write("  ".join(bits))
            loc = []
            if city:
                loc.append(self._kv("city", str(city)))
            if u.get("home_town"):
                loc.append(self._kv("home", str(u["home_town"])))
            if u.get("bdate"):
                loc.append(self._kv("bdate", str(u["bdate"])))
            if loc:
                self.write("  ".join(loc))
            cnt = []
            for k in ("friends", "followers", "groups", "photos", "videos", "notes"):
                if counters.get(k) is not None:
                    cnt.append(self.sty(str(counters[k]), "bold") + " " + k)
            if cnt:
                self.write("  ".join(cnt))

            def block(title: str, text: str) -> None:
                self.write(self.sty(title, "bold", "yellow"))
                for line in _wrap_lines(text, self.width() - 2, self.ansi):
                    self.write(" " + line)

            if u.get("status"):
                block("mood", str(u["status"]))
            if u.get("about"):
                block("about", str(u["about"]))
            if u.get("interests"):
                block("interests", str(u["interests"]))
            self.write(self.rule())
            self.write("  ".join(keys))
            key = self.io.read_key()
            if key is None or key in ("q", "Q", "esc"):
                return
            if key in ("w", "W"):
                self.do_user_wall(uid, name)
                continue
            if key in ("m", "M") and not mine:
                self.do_chat({"peer_id": uid, "author": name})
                continue
            if key in ("f", "F") and not mine:
                try:
                    if st in (0, 2):
                        self.api.friends_add(uid)
                    elif st == 3:
                        self.api.friends_delete(uid)
                except OvkApiError as exc:
                    self.write()
                    self.write("  %s" % exc)
                    self.prompt("  [Enter] ")
                continue

    def do_user_wall(self, uid: int, name: str = "") -> None:
        if not self.api:
            return
        off = [0]

        def page():
            payload = self.api.wall_get(uid, offset=off[0], count=15)
            return [_as_post_card(p) for p in normalize_posts(payload)]

        try:
            cards = page()
        except OvkApiError as exc:
            self.write("  %s" % exc)
            self.prompt("  [Enter] ")
            return

        def load_more():
            off[0] += 15
            try:
                return page()
            except OvkApiError:
                return []

        def write(card: dict) -> None:
            msg = self.compose("Post on wall")
            if not msg:
                return
            try:
                pid = self.api.wall_post(msg, owner_id=uid)
            except OvkApiError as exc:
                self.write("  %s" % exc)
                self.prompt("  [Enter] ")
                return
            self.write("  posted  wall%s_%s" % (uid, pid))
            self.prompt("  [Enter] ")

        title = "WALL  " + (name or ("id%s" % uid))
        self._reader(
            title,
            cards,
            load_more=load_more,
            comments_of=self.do_comments,
            write_of=write,
            profile_of=self.do_profile,
        )

    def do_friends(self) -> None:
        if not self.require_auth():
            return
        while self.io.alive:
            self.io.cls()
            self.write_heading(self.sty("FRIENDS", "bold"))
            self.write("  " + self.sty("1", "bold", "yellow") + "  all")
            self.write("  " + self.sty("2", "bold", "yellow") + "  incoming")
            self.write("  " + self.sty("3", "bold", "yellow") + "  outgoing")
            self.write()
            self.write(self.rule())
            self.write(
                self.sty("1-3", "dim") + "   "
                + self.sty("Q", "bold", "yellow") + " back"
            )
            key = self.io.read_key()
            if key is None or key in ("q", "Q", "esc"):
                return
            if key == "1":
                self._friends_roster()
            elif key == "2":
                self._friends_requests(outgoing=False)
            elif key == "3":
                self._friends_requests(outgoing=True)

    def _friend_cards(self, items: list, tag: str) -> list[dict]:
        cards = []
        for u in items:
            if isinstance(u, int):
                cards.append({
                    "author": "id%s" % u,
                    "date": tag,
                    "meta": "id%s" % u,
                    "profile_id": u,
                })
                continue
            if not isinstance(u, dict) or u.get("id") is None:
                continue
            uid = int(u["id"])
            name = ((u.get("first_name") or "") + " " + (u.get("last_name") or "")).strip() or ("id%s" % uid)
            on = tag
            if tag in ("", "friend"):
                on = "online" if int(u.get("online") or 0) else "offline"
            cards.append({
                "author": name,
                "date": on,
                "meta": "id%s" % uid,
                "profile_id": uid,
            })
        return cards

    def _friends_roster(self) -> None:
        assert self.api is not None
        off = [0]

        def fetch():
            payload = self.api.friends_get(offset=off[0], count=50)
            return self._friend_cards(_as_list(payload.get("items")), "friend")

        try:
            cards = fetch()
        except OvkApiError as exc:
            self.write("  %s" % exc)
            self.prompt("  [Enter] ")
            return

        def load_more():
            off[0] += 50
            try:
                return fetch()
            except OvkApiError:
                return []

        def unfriend(card: dict) -> bool:
            uid = self._uid(card)
            if not uid:
                return False
            try:
                self.api.friends_delete(uid)
            except OvkApiError as extra:
                self.write()
                self.write("  %s" % extra)
                self.prompt("  [Enter] ")
                return False
            return True

        self._pick_list(
            "FRIENDS",
            cards,
            load_more=load_more,
            on_open=self.do_profile,
            extra={k: unfriend for k in "uU"},
            extra_hint=self.sty("U", "bold", "yellow") + " unfriend   ",
        )

    def _friends_requests(self, outgoing: bool) -> None:
        assert self.api is not None
        off = [0]
        title = "OUTGOING" if outgoing else "INCOMING"
        tag = "out" if outgoing else "in"

        def fetch():
            payload = self.api.friends_get_requests(out=1 if outgoing else 0, offset=off[0], count=50)
            return self._friend_cards(_as_list(payload.get("items")), tag)

        try:
            cards = fetch()
        except OvkApiError as extra:
            self.write("  %s" % extra)
            self.prompt("  [Enter] ")
            return

        def load_more():
            off[0] += 50
            try:
                return fetch()
            except OvkApiError:
                return []

        def accept(card: dict) -> bool:
            uid = self._uid(card)
            if not uid:
                return False
            try:
                self.api.friends_add(uid)
            except OvkApiError as exc:
                self.write()
                self.write("  %s" % exc)
                self.prompt("  [Enter] ")
                return False
            return True

        extra = {}
        extra_hint_txt = ""
        if not outgoing:
            extra = {k: accept for k in "yYaA"}
            extra_hint_txt = self.sty("Y", "bold", "yellow") + " accept   "
        self._pick_list(
            title,
            cards,
            load_more=load_more,
            on_open=self.do_profile,
            extra=extra,
            extra_hint=extra_hint_txt,
        )

    def do_logoff(self) -> None:
        if self.api:
            self.api.logout()
        self.write("  logged off.")
        self.prompt("  [Enter] ")

    def do_ansi(self) -> None:
        self.ansi = not self.ansi
        _save_state({"ansi": self.ansi})
        self.write()
        self.write("  ANSI " + self.sty("ON" if self.ansi else "OFF", "bold"))
        self.prompt("  [Enter] ")

    def do_codepage(self) -> None:
        self.write()
        for num, enc, label in CODEPAGES:
            mark = "*" if self.io.encoding == enc else " "
            self.write("  %s%s  %s" % (num, mark, label))
        ans = self.prompt("  : ")
        if not ans:
            return
        mapping = {row[0]: row[1] for row in CODEPAGES}
        enc = mapping.get(ans.strip())
        if not enc:
            self.write("  unknown.")
            return
        self.io.encoding = enc
        _save_state({"encoding": enc})
        self.write("  ok, %s" % enc)
        self.prompt("  [Enter] ")

    def loop(self) -> None:
        self.io.negotiate()
        self.io.hayes_wait()
        self.ansi = bool(self.io.telnet)
        self.detect_encoding()
        if self.default_instance:
            self.set_instance(self.default_instance)
            self.io.drain_until_quiet(quiet=0.2, max_wait=1.0)
        menu_keys = set("12345678cagqx")
        while self.io.alive:
            self.draw_menu()
            self.io.drain_until_quiet(quiet=0.35, max_wait=3.0)
            self.io._buf.clear()
            self.io.block()
            ignore_until = time.time() + (0.0 if self.io.telnet else 0.4)
            allowed = menu_keys | {k.upper() for k in menu_keys}
            key = None
            while self.io.alive:
                got = self.io.read_key()
                if got is None:
                    if not self.io.alive:
                        return
                    continue
                if time.time() < ignore_until:
                    continue
                if got not in allowed:
                    continue
                extra = False
                while True:
                    nxt = self.io.read_key(timeout=0.12)
                    if nxt is None:
                        break
                    if nxt in ("enter", "esc"):
                        continue
                    extra = True
                    break
                if extra:
                    continue
                key = got
                break
            if key is None:
                return
            self.io.send_raw(key.encode("ascii", "replace") + b"\r\n")
            choice = key.lower()
            try:
                if choice in ("g", "0", "q", "x"):
                    self.write("\n  dropped.")
                    break
                if choice == "1":
                    self.write("1\n")
                    self.do_node()
                elif choice == "2":
                    self.do_login()
                elif choice == "3":
                    self.do_feed(False)
                elif choice == "4":
                    self.do_feed(True)
                elif choice == "5":
                    self.write("5\n")
                    self.do_post()
                elif choice == "7":
                    self.do_mail()
                elif choice == "8":
                    self.do_friends()
                elif choice == "6":
                    self.write("6\n")
                    self.do_logoff()
                elif choice == "c":
                    self.write("C\n")
                    self.do_codepage()
                elif choice == "a":
                    self.write("A\n")
                    self.do_ansi()
            except OvkApiError as exc:
                self.write("  %s" % exc)
                self.prompt("  [Enter] ")
            except Exception as exc:
                self.write("  error: %s" % exc)
                self.prompt("  [Enter] ")


def handle_client(conn: socket.socket, addr: object, default_instance: Optional[str], encoding: Optional[str]) -> None:
    conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    io = LineIO(sock=conn, encoding=encoding or "utf-8")
    io.peer = "%s:%s" % (addr[0], addr[1]) if isinstance(addr, tuple) and addr else str(addr)
    try:
        Session(io, default_instance=default_instance, skip_detect=bool(encoding)).loop()
    except Exception:
        import traceback
        traceback.print_exc()
    finally:
        io.close()


def serve(host: str, port: int, default_instance: Optional[str], encoding: Optional[str]) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(32)
    print("LainTel: %s:%s." % (host, port), flush=True)

    try:
        while True:
            conn, addr = sock.accept()
            threading.Thread(
                target=handle_client,
                args=(conn, addr, default_instance, encoding),
                daemon=True,
            ).start()
    except KeyboardInterrupt:
        print("\nstop")
    finally:
        sock.close()


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="OpenVK telnet node")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=2323)
    parser.add_argument("--instance", default="https://lainlife.org")
    parser.add_argument("--encoding", default="", help="skip detect: utf-8 / cp866 / cp1251")
    parser.add_argument("--stdio", action="store_true")
    args = parser.parse_args(argv)
    instance = args.instance.strip() or None
    if instance:
        instance = normalize_instance(instance)
    forced = _enc_name(args.encoding) if args.encoding else None
    if args.stdio:
        io = LineIO(stdio=True, encoding=forced or "utf-8")
        Session(io, default_instance=instance, skip_detect=True).loop()
        return 0
    serve(args.host, args.port, instance, forced)
    return 0


if __name__ == "__main__":
    sys.exit(main())
