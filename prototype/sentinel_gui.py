#!/usr/bin/env python3
"""Local web dashboard for IP Sentinel.

    python3 sentinel_gui.py [--workspace DIR] [--storage DIR] [--port N] [--no-browser]

The server listens on 127.0.0.1 only. Every /api/ call must carry the per-launch
token embedded in the served page, and requests with a foreign Host or Origin are
rejected, so other websites open in the same browser cannot drive the ledger.
"""

from __future__ import annotations

import argparse
import hmac
import json
import mimetypes
import re
import secrets
import sys
import threading
import webbrowser
from collections import Counter, deque
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from ip_sentinel import IPSentinel

APP_DIR = Path(__file__).resolve().parent
GUI_DIR = APP_DIR / "gui"
DEFAULT_STORAGE = APP_DIR / "sentinel_data"
DEFAULT_PORT = 8787
TOKEN_PLACEHOLDER = "{{SENTINEL_TOKEN}}"
SETTINGS_FILE = "gui_settings.json"
MAX_BODY_BYTES = 32 * 1024 * 1024
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_BLOCK_PATH_RE = re.compile(r"^/api/blocks/(\d+)$")

CONTENT_SECURITY_POLICY = (
    "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self'; "
    "frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class ApiError(Exception):
    def __init__(self, status: HTTPStatus, message: str, code: str = "error") -> None:
        super().__init__(message)
        self.status = status
        self.code = code


class Dashboard:
    """Application state shared by all request threads."""

    def __init__(self, sentinel: IPSentinel, workspace: str | None) -> None:
        self.sentinel = sentinel
        self.lock = threading.Lock()
        self.activity: deque[dict] = deque(maxlen=500)
        self.started_at = _utc_now()
        self.settings_path = sentinel.storage_dir / SETTINGS_FILE
        self.workspace: Path | None = None

        remembered = self._load_settings().get("workspace")
        initial = workspace or remembered
        if initial:
            try:
                self.set_workspace(initial, announce=False)
            except ApiError as exc:
                self.log("warning", f"Workspace not loaded: {exc}")
        self.log("info", f"Dashboard started; ledger at {sentinel.storage_dir.resolve()}")

    # -- helpers ---------------------------------------------------------------

    def log(self, level: str, message: str) -> None:
        self.activity.append({"time": _utc_now(), "level": level, "message": message})

    def _load_settings(self) -> dict:
        try:
            data = json.loads(self.settings_path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}

    def _save_settings(self) -> None:
        data = {"workspace": str(self.workspace) if self.workspace else None}
        self.settings_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def _require_workspace(self) -> Path:
        if self.workspace is None:
            raise ApiError(HTTPStatus.BAD_REQUEST, "No workspace selected", "no_workspace")
        if not self.workspace.is_dir():
            raise ApiError(HTTPStatus.BAD_REQUEST, f"Workspace no longer exists: {self.workspace}", "no_workspace")
        return self.workspace

    def _chain_or_empty(self) -> list:
        try:
            return self.sentinel.get_chain()
        except (OSError, ValueError):
            return []

    # -- operations --------------------------------------------------------------

    def set_workspace(self, raw_path: str, announce: bool = True) -> None:
        if not isinstance(raw_path, str) or not raw_path.strip():
            raise ApiError(HTTPStatus.BAD_REQUEST, "Workspace path is required", "invalid_path")
        path = Path(raw_path.strip()).expanduser().resolve()
        if not path.is_dir():
            raise ApiError(HTTPStatus.BAD_REQUEST, f"Not a folder: {path}", "invalid_path")
        self.workspace = path
        self._save_settings()
        if announce:
            self.log("info", f"Workspace set to {path}")

    def state(self) -> dict:
        chain = self._chain_or_empty()
        integrity = self.sentinel.verify_integrity().to_dict()
        tracked = {e.get("relative_path") for b in chain if isinstance(b, dict) for e in b.get("entries", [])}
        blocks = []
        for block in chain:
            if not isinstance(block, dict):
                continue
            counts = Counter(e.get("status") for e in block.get("entries", []))
            blocks.append({
                "index": block.get("index"),
                "timestamp": block.get("timestamp"),
                "author": block.get("author"),
                "file_count": block.get("file_count"),
                "previous_block_hash": block.get("previous_block_hash"),
                "block_hash": block.get("block_hash"),
                "counts": {k: counts.get(k, 0) for k in ("new", "modified", "unchanged")},
            })
        last = blocks[-1] if blocks else None
        return {
            "server": {"started_at": self.started_at, "storage_dir": str(self.sentinel.storage_dir.resolve())},
            "workspace": str(self.workspace) if self.workspace else None,
            "workspace_exists": bool(self.workspace and self.workspace.is_dir()),
            "integrity": integrity,
            "chain_length": len(blocks),
            "head_block_hash": last["block_hash"] if last else None,
            "files_in_head": last["file_count"] if last else 0,
            "files_ever_tracked": len(tracked),
            "last_commit": last,
            "blocks": blocks,
        }

    def scan(self) -> dict:
        workspace = self._require_workspace()
        files = self.sentinel.scan_and_discover(workspace)
        counts = Counter(f["status"] for f in files)
        summary = {
            "total": len(files),
            "new": counts.get("new", 0),
            "modified": counts.get("modified", 0),
            "unchanged": counts.get("unchanged", 0),
            "total_bytes": sum(f["size_bytes"] for f in files),
        }
        self.log("info", f"Scanned {workspace.name}: {summary['total']} files "
                         f"({summary['new']} new, {summary['modified']} modified, {summary['unchanged']} unchanged)")
        return {"workspace": str(workspace), "scanned_at": _utc_now(), "summary": summary, "files": files}

    def commit(self, author: object, expected: object) -> dict:
        workspace = self._require_workspace()
        if not isinstance(author, str) or not author.strip():
            raise ApiError(HTTPStatus.BAD_REQUEST, "Author is required", "invalid_author")
        if not isinstance(expected, list) or not expected:
            raise ApiError(HTTPStatus.BAD_REQUEST, "Scan the workspace before committing", "no_scan")
        try:
            reviewed = {(item["relative_path"], item["sha256_hash"]) for item in expected}
        except (TypeError, KeyError):
            raise ApiError(HTTPStatus.BAD_REQUEST, "Malformed scan results", "invalid_scan") from None

        # Commit only what the user reviewed: rescan and refuse if anything changed since.
        fresh = self.sentinel.scan_and_discover(workspace)
        if {(f["relative_path"], f["sha256_hash"]) for f in fresh} != reviewed:
            raise ApiError(HTTPStatus.CONFLICT,
                           "Files changed since the last scan. Rescan and review before committing.",
                           "workspace_changed")
        try:
            block = self.sentinel.commit_custody_log(fresh, author=author)
        except RuntimeError as exc:
            raise ApiError(HTTPStatus.CONFLICT, str(exc), "ledger_tampered") from None
        self.log("success", f"Committed block #{block['index']} ({block['file_count']} files) "
                            f"hash {block['block_hash'][:16]}…")
        return {"block": block}

    def block(self, index: int) -> dict:
        chain = self._chain_or_empty()
        if index >= len(chain):
            raise ApiError(HTTPStatus.NOT_FOUND, f"Block #{index} does not exist", "not_found")
        return {"block": chain[index]}

    def verify(self) -> dict:
        report = self.sentinel.verify_integrity()
        if report:
            self.log("success", f"Integrity audit passed: {report}")
        else:
            self.log("error", f"Integrity audit failed: {report}")
        return {"checked_at": _utc_now(), **report.to_dict()}

    def lookup(self, sha256_hash: str) -> dict:
        target = (sha256_hash or "").strip().lower()
        if not _SHA256_RE.match(target):
            raise ApiError(HTTPStatus.BAD_REQUEST, "Expected a 64-character hex SHA-256 hash", "invalid_hash")
        matches = self.sentinel.find_file_hash(target)
        if matches:
            self.log("info", f"Lookup {target[:16]}…: found in {len(matches)} block(s), "
                             f"first recorded in block #{matches[0]['block_index']}")
        else:
            self.log("warning", f"Lookup {target[:16]}…: not in ledger")
        return {"sha256": target, "matches": matches}

    def export(self) -> tuple[dict, str]:
        package = self.sentinel.generate_verification_package()
        head = (package.get("head_block_hash") or "empty")[:12]
        self.log("info", f"Exported verification package ({package['chain_length']} blocks)")
        return package, f"ip-sentinel-proof-{head}.json"


class Handler(BaseHTTPRequestHandler):
    server_version = "IPSentinel"
    sys_version = ""
    server: "DashboardServer"

    def log_message(self, format: str, *args) -> None:  # keep the terminal quiet
        pass

    def do_GET(self) -> None:
        self._dispatch("GET")

    def do_POST(self) -> None:
        self._dispatch("POST")

    # -- request plumbing ------------------------------------------------------

    def _dispatch(self, method: str) -> None:
        try:
            if self.headers.get("Host") not in self.server.allowed_hosts:
                raise ApiError(HTTPStatus.FORBIDDEN, "Unrecognized Host header", "forbidden")
            parsed = urlparse(self.path)
            if parsed.path.startswith("/api/"):
                self._check_token()
                if method == "POST":
                    origin = self.headers.get("Origin")
                    if origin and origin not in self.server.allowed_origins:
                        raise ApiError(HTTPStatus.FORBIDDEN, "Cross-origin request refused", "forbidden")
                self._api(method, parsed.path, parse_qs(parsed.query))
            elif method == "GET":
                self._static(parsed.path)
            else:
                raise ApiError(HTTPStatus.METHOD_NOT_ALLOWED, "Method not allowed", "method_not_allowed")
        except ApiError as exc:
            self._send_json(exc.status, {"error": str(exc), "code": exc.code})
        except Exception as exc:  # surface unexpected failures to the UI and activity log
            self.server.dashboard.log("error", f"Internal error: {exc}")
            self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": str(exc), "code": "internal"})

    def _check_token(self) -> None:
        supplied = self.headers.get("X-Sentinel-Token", "")
        if not hmac.compare_digest(supplied.encode(), self.server.token.encode()):
            raise ApiError(HTTPStatus.UNAUTHORIZED, "Missing or invalid session token. Reload the page.", "unauthorized")

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_BODY_BYTES:
            raise ApiError(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "Request body too large", "too_large")
        if length == 0:
            return {}
        try:
            body = json.loads(self.rfile.read(length))
        except ValueError:
            raise ApiError(HTTPStatus.BAD_REQUEST, "Request body is not valid JSON", "invalid_json") from None
        if not isinstance(body, dict):
            raise ApiError(HTTPStatus.BAD_REQUEST, "Request body must be a JSON object", "invalid_json")
        return body

    def _api(self, method: str, path: str, query: dict) -> None:
        dash = self.server.dashboard
        block_match = _BLOCK_PATH_RE.match(path)
        with dash.lock:
            if method == "GET" and path == "/api/state":
                return self._send_json(HTTPStatus.OK, dash.state())
            if method == "GET" and path == "/api/activity":
                return self._send_json(HTTPStatus.OK, {"events": list(dash.activity)})
            if method == "GET" and block_match:
                return self._send_json(HTTPStatus.OK, dash.block(int(block_match.group(1))))
            if method == "GET" and path == "/api/lookup":
                return self._send_json(HTTPStatus.OK, dash.lookup(query.get("sha256", [""])[0]))
            if method == "GET" and path == "/api/export":
                package, filename = dash.export()
                body = json.dumps(package, indent=2, ensure_ascii=False).encode("utf-8")
                return self._send_bytes(HTTPStatus.OK, body, "application/json; charset=utf-8",
                                        {"Content-Disposition": f'attachment; filename="{filename}"'})
            if method == "POST" and path == "/api/workspace":
                dash.set_workspace(self._read_json().get("path"))
                return self._send_json(HTTPStatus.OK, dash.state())
            if method == "POST" and path == "/api/scan":
                return self._send_json(HTTPStatus.OK, dash.scan())
            if method == "POST" and path == "/api/commit":
                body = self._read_json()
                return self._send_json(HTTPStatus.OK, dash.commit(body.get("author"), body.get("expected")))
            if method == "POST" and path == "/api/verify":
                return self._send_json(HTTPStatus.OK, dash.verify())
        raise ApiError(HTTPStatus.NOT_FOUND, f"Unknown endpoint: {method} {path}", "not_found")

    def _static(self, path: str) -> None:
        if path in ("/", "/index.html"):
            html = (GUI_DIR / "index.html").read_text(encoding="utf-8")
            body = html.replace(TOKEN_PLACEHOLDER, self.server.token).encode("utf-8")
            return self._send_bytes(HTTPStatus.OK, body, "text/html; charset=utf-8")
        target = (GUI_DIR / path.lstrip("/")).resolve()
        if not target.is_relative_to(GUI_DIR) or not target.is_file():
            raise ApiError(HTTPStatus.NOT_FOUND, "Not found", "not_found")
        content_type = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
        self._send_bytes(HTTPStatus.OK, target.read_bytes(), content_type)

    def _send_json(self, status: HTTPStatus, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self._send_bytes(status, body, "application/json; charset=utf-8")

    def _send_bytes(self, status: HTTPStatus, body: bytes, content_type: str, extra: dict | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", CONTENT_SECURITY_POLICY)
        for name, value in (extra or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)


class DashboardServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, port: int, dashboard: Dashboard) -> None:
        super().__init__(("127.0.0.1", port), Handler)
        self.dashboard = dashboard
        self.token = secrets.token_urlsafe(32)
        actual = self.server_address[1]
        self.allowed_hosts = {f"127.0.0.1:{actual}", f"localhost:{actual}"}
        self.allowed_origins = {f"http://{host}" for host in self.allowed_hosts}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the IP Sentinel dashboard on localhost.")
    parser.add_argument("--workspace", help="folder to scan (remembered between launches)")
    parser.add_argument("--storage", default=str(DEFAULT_STORAGE), help="ledger folder (default: %(default)s)")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="port on 127.0.0.1 (default: %(default)s)")
    parser.add_argument("--no-browser", action="store_true", help="do not open a browser window")
    args = parser.parse_args(argv)

    if not (GUI_DIR / "index.html").is_file():
        print(f"Missing {GUI_DIR / 'index.html'}", file=sys.stderr)
        return 1

    dashboard = Dashboard(IPSentinel(storage_dir=args.storage), args.workspace)
    try:
        server = DashboardServer(args.port, dashboard)
    except OSError:
        print(f"Port {args.port} is busy; using a free port instead.", file=sys.stderr)
        server = DashboardServer(0, dashboard)

    url = f"http://127.0.0.1:{server.server_address[1]}/"
    print(f"IP Sentinel dashboard running at {url}  (Ctrl+C to stop)", flush=True)
    if not args.no_browser:
        threading.Timer(0.4, webbrowser.open, args=(url,)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping dashboard.")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
