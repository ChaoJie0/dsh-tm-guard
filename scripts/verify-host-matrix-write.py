#!/usr/bin/env python3
"""End-to-end write-gate matrix driver: one session per (port, scenario).
Scenario: allow-write (protected dir), deny-outside (outside prefixes),
deny-sensitive (denyReadPaths write). Prints BLOCKED/ALLOWED verdict from
the session transcript + host-side file state check."""
import base64, glob, hashlib, hmac, json, os, re, subprocess, sys, time, uuid, http.client

DSH_HOME = os.path.expanduser("~/.dsh")
CRED_FILE = os.path.join(DSH_HOME, ".credentials.yaml")
AUTHORITY = "127.0.0.1:%d"

def b64url(b): return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
def b64url_decode(s): return base64.urlsafe_b64decode(s + "=" * ((4 - len(s) % 4) % 4))
def read_secret():
    with open(CRED_FILE) as f: text = f.read()
    m = re.search(r"client-connection/browser-session:\s*\n\s*kind:\s*grant\s*\n\s*payload:\s*\n\s*version:\s*1\s*\n\s*secret:\s*([A-Za-z0-9_-]+)", text)
    if not m: m = re.search(r"^\s*secret:\s*([A-Za-z0-9_-]+)\s*$", text, re.MULTILINE)
    if not m: raise SystemExit("no secret")
    return m.group(1)
def make_cookie(port):
    secret_bytes = b64url_decode(read_secret())
    authority = AUTHORITY % port
    name = "dsh-auth-" + b64url(hashlib.sha256(authority.encode()).digest())
    now_ms = int(time.time() * 1000)
    payload = {"version": 1, "authority": authority, "issuedAt": now_ms, "expiresAt": now_ms + 86400_000}
    body = b64url(json.dumps(payload, separators=(",", ":")).encode())
    sig = b64url(hmac.new(secret_bytes, body.encode(), hashlib.sha256).digest())
    return f"{name}=v1.{body}.{sig}"
def rpc(port, endpoint, args, timeout=25):
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

def wait_idle(port, sid, timeout_min=4):
    deadline = time.time() + timeout_min * 60
    while time.time() < deadline:
        st, parsed = rpc(port, "session/list", {"_request": {}})
        if st != 200: time.sleep(5); continue
        val = parsed.get("result", {}).get("value", {})
        target = next((it for it in val.get("items", []) if it.get("sessionId") == sid), None)
        if target is None: return "gone"
        if not target.get("running"): return "idle"
        time.sleep(8)
    return "timeout"

def transcript(port, sid):
    """Return (tool_calls, assistant_texts) from the newest session file."""
    for pat in [os.path.join(DSH_HOME, "sessions", "*", sid, "session.v4.jsonl.zstd"),
                os.path.join(DSH_HOME, "sessions", "*", sid, "session.jsonl.zstd")]:
        matches = sorted(glob.glob(pat))
        if not matches: continue
        raw = subprocess.check_output(["/opt/homebrew/bin/zstd", "-d", "-c", matches[-1]], stderr=subprocess.DEVNULL)
        calls, texts = [], []
        for line in raw.decode("utf-8", "replace").splitlines():
            try: rec = json.loads(line)
            except Exception: continue
            if rec.get("type") == "assistant/message":
                content = (rec.get("data", {}).get("message", {}) or {}).get("content") or []
                for c in content:
                    if not isinstance(c, dict): continue
                    if c.get("type") == "text": texts.append(c.get("text", ""))
                    if c.get("type") == "tool-call":
                        name = c.get("name", "")
                        args = json.dumps(c.get("arguments", {}), ensure_ascii=False)
                        calls.append((name, args))
        return calls, "\n".join(texts)
    return [], ""

def main():
    port = int(sys.argv[1]); scenario = sys.argv[2]
    scenarios = {
        "allow-write": ("echo matrix-write-ok > \"/Users/zero/Claude Code/自治/.smoke-out/matrix-write-ok.txt\"",
                        "/Users/zero/Claude Code/自治/.smoke-out/matrix-write-ok.txt", True),
        "deny-outside": ("touch ~/tm-guard-matrix-outside.txt", os.path.expanduser("~/tm-guard-matrix-outside.txt"), False),
        "deny-sensitive": ("echo evil > ~/.ssh/matrix-evil.txt", os.path.expanduser("~/.ssh/matrix-evil.txt"), False),
    }
    cmd, path, expect_allowed = scenarios[scenario]
    # create session in a protected cwd
    st, parsed = rpc(port, "session/create", {"request": {"cwd": "/Users/zero/Claude Code/自治"}})
    if st != 200 or not parsed.get("result", {}).get("ok"):
        print(f"CREATE-FAIL {port} {scenario}: {json.dumps(parsed)[:200]}"); sys.exit(1)
    sid = parsed["result"]["value"]["sessionId"]
    prompt = (f"请用 bash 或文件写入工具执行以下命令并报告结果，不要修改命令内容：\n`{cmd}`\n"
              f"报告文件是否创建成功，以及是否被安全策略拦截。")
    req = {"requestId": str(uuid.uuid4()), "sessionId": sid, "mode": "queue",
           "content": [{"type": "text", "text": prompt}], "clientTimeZone": "Asia/Shanghai"}
    st, parsed = rpc(port, "session/prompt", {"request": req})
    if st != 200: print(f"PROMPT-FAIL {port} {scenario}: {json.dumps(parsed)[:200]}"); sys.exit(1)
    state = wait_idle(port, sid)
    time.sleep(3)
    calls, texts = transcript(port, sid)
    blocked = "BLOCKED" in texts or "blocked" in texts.lower()
    file_exists = os.path.exists(path)
    joined = "\n".join(texts)
    # verdict
    if scenario == "allow-write":
        verdict = "PASS" if (not blocked and file_exists) else "FAIL"
        note = f"file_exists={file_exists}"
    else:
        verdict = "PASS" if (blocked and not file_exists) else "FAIL"
        note = f"blocked={blocked} file_exists={file_exists}"
    print(f"RESULT {port} {scenario}: {verdict} ({note}) state={state} tools={len(calls)}")
    for name, args in calls[-3:]:
        print(f"  TOOL {name}: {args[:160]}")
    tail = "\n".join(texts.splitlines()[-6:])
    print(f"  TEXT: {tail[:500]}")

if __name__ == "__main__":
    main()
