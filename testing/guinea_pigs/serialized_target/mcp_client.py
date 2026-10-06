"""Minimal MCP (streamable HTTP) client for the RedAmon inbound server.

Reads MCP_SERVER_TOKEN from the repo .env and never prints it.
Usage:  python3 mcp.py list
        python3 mcp.py call <tool> '<json-args>'
"""
import json, os, sys, urllib.request

REPO = os.environ.get("REDAMON_REPO", os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..")))
URL = os.environ.get("MCP_URL", "http://localhost:3000/api/mcp-server")


def _token():
    for line in open(os.path.join(REPO, ".env")):
        if line.startswith("MCP_SERVER_TOKEN="):
            return line.split("=", 1)[1].strip().strip('"').strip("'")
    raise SystemExit("MCP_SERVER_TOKEN missing from .env")


TOKEN = _token()
SESSION = {"id": None}


def _post(payload, timeout=600):
    headers = {"Content-Type": "application/json",
               "Accept": "application/json, text/event-stream",
               "Authorization": f"Bearer {TOKEN}"}
    if SESSION["id"]:
        headers["Mcp-Session-Id"] = SESSION["id"]
    req = urllib.request.Request(URL, data=json.dumps(payload).encode(), headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        sid = resp.headers.get("Mcp-Session-Id")
        if sid:
            SESSION["id"] = sid
        body = resp.read().decode()
        ctype = resp.headers.get("Content-Type", "")
    if "text/event-stream" in ctype:
        for line in body.splitlines():
            if line.startswith("data:"):
                return json.loads(line[5:].strip())
        return None
    return json.loads(body) if body.strip() else None


_ID = {"n": 0}


def rpc(method, params=None, timeout=600):
    _ID["n"] += 1
    out = _post({"jsonrpc": "2.0", "id": _ID["n"], "method": method, "params": params or {}}, timeout)
    if out and "error" in out:
        raise RuntimeError(json.dumps(out["error"]))
    return (out or {}).get("result")


def init():
    rpc("initialize", {"protocolVersion": "2025-03-26", "capabilities": {},
                       "clientInfo": {"name": "redamon-e2e", "version": "1"}})
    try:
        _post({"jsonrpc": "2.0", "method": "notifications/initialized"})
    except Exception:
        pass


def call(tool, args, timeout=600):
    res = rpc("tools/call", {"name": tool, "arguments": args}, timeout)
    texts = [c.get("text", "") for c in (res or {}).get("content", []) if c.get("type") == "text"]
    joined = "\n".join(texts)
    try:
        return json.loads(joined), res.get("isError", False)
    except Exception:
        return joined, res.get("isError", False)


if __name__ == "__main__":
    init()
    if sys.argv[1] == "list":
        tools = rpc("tools/list")["tools"]
        for t in tools:
            print(t["name"])
    elif sys.argv[1] == "schema":
        for t in rpc("tools/list")["tools"]:
            if t["name"] == sys.argv[2]:
                print(json.dumps(t, indent=1))
    elif sys.argv[1] == "call":
        out, err = call(sys.argv[2], json.loads(sys.argv[3]) if len(sys.argv) > 3 else {})
        print("isError:", err)
        print(json.dumps(out, indent=1) if not isinstance(out, str) else out)
