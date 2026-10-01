#!/usr/bin/env python3
"""Parameterized dsh RPC smoke client for the 5-host tm-guard matrix.
Usage: tm-rpc.py <port> <endpoint> [json-args]
       tm-rpc.py <port> status-check      # session/list + version probe
"""
import base64, glob, hashlib, hmac, json, os, re, subprocess, sys, time, uuid, http.client

DSH_HOME = os.path.expanduser("~/.dsh")
CRED_FILE = os.path.join(DSH_HOME, ".credentials.yaml")

def b64url(b): return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
def b64url_decode(s): return base64.urlsafe_b64decode(s + "=" * ((4 - len(s) % 4) % 4))

def read_secret():
    with open(CRED_FILE) as f: text = f.read()
    m = re.search(r"client-connection/browser-session:\s*\n\s*kind:\s*grant\s*\n\s*payload:\s*\n\s*version:\s*1\s*\n\s*secret:\s*([A-Za-z0-9_-]+)", text)
    if not m:
        m = re.search(r"^\s*secret:\s*([A-Za-z0-9_-]+)\s*$", text, re.MULTILINE)
    if not m: raise SystemExit("no secret")
    return m.group(1)

def make_cookie(port):
    secret_bytes = b64url_decode(read_secret())
    authority = f"127.0.0.1:{port}"
    name = "dsh-auth-" + b64url(hashlib.sha256(authority.encode()).digest())
    now_ms = int(time.time() * 1000)
    payload = {"version": 1, "authority": authority, "issuedAt": now_ms, "expiresAt": now_ms + 86400_000}
    body = b64url(json.dumps(payload, separators=(",", ":")).encode())
    sig = b64url(hmac.new(secret_bytes, body.encode(), hashlib.sha256).digest())
    return f"{name}=v1.{body}.{sig}"

def rpc(port, endpoint, args, timeout=20):
    envelope = {"type": "client-request", "rpcId": str(uuid.uuid4()), "method": endpoint, "payload": {"args": args}}
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    conn.request("POST", f"/api/{endpoint}", body=json.dumps(envelope),
                 headers={"Host": f"127.0.0.1:{port}", "Cookie": make_cookie(port), "Content-Type": "application/json"})
    try:
        resp = conn.getresponse(); data = resp.read().decode()
    except Exception as e:
        return None, {"error": str(e)}
    finally:
        conn.close()
    try: parsed = json.loads(data)
    except json.JSONDecodeError: parsed = {"raw": data}
    return resp.status, parsed

def main():
    port = int(sys.argv[1]); cmd = sys.argv[2]
    if cmd == "status-check":
        st, parsed = rpc(port, "session/list", {"_request": {}})
        print(f"port {port} session/list -> HTTP {st}, ok={parsed.get('result',{}).get('ok')}")
        if st == 200:
            items = parsed.get("result", {}).get("value", {}).get("items", [])
            print(f"  sessions: {len(items)}")
        return 0 if st == 200 else 1
    endpoint = cmd
    args = json.loads(sys.argv[3]) if len(sys.argv) > 3 else {}
    st, parsed = rpc(port, endpoint, args)
    print(json.dumps({"http": st, "result": parsed.get("result", {})}, ensure_ascii=False, indent=1)[:1500])
    return 0 if st == 200 else 1

if __name__ == "__main__":
    sys.exit(main())
