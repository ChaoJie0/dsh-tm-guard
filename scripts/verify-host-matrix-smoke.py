#!/usr/bin/env python3
"""Batch tm_status gate smoke across the remaining host instances.
Creates a session on each port, prompts the agent to call tm_status,
polls the v4 session file, and asserts the gate output is present.
"""
import json, os, subprocess, sys, time, urllib.request

_rpc_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "verify-host-matrix-rpc.py")
_ns = {"__name__": "tm_rpc_lib"}
exec(open(_rpc_path).read(), _ns)  # defines rpc/make_cookie without running main
rpc = _ns["rpc"]

def read_v4(sid):
    pat = f"/Users/zero/.dsh/sessions/--Users-zero-DSH_Work--/{sid}/session.v4.jsonl.zstd"
    if not os.path.exists(pat): return ""
    try:
        raw = subprocess.check_output(["/opt/homebrew/bin/zstd", "-d", "-c", pat], stderr=subprocess.DEVNULL)
    except Exception:
        return ""
    texts = []
    for line in raw.decode("utf-8", "replace").splitlines():
        try: rec = json.loads(line)
        except Exception: continue
        t = rec.get("type", "")
        if t == "tool/call" and rec.get("data", {}).get("name") == "tm_status":
            texts.append("TM_STATUS_CALLED")
        if t == "assistant/message":
            content = ((rec.get("data", {}).get("message", {}) or {}).get("content") or [])
            for c in content:
                if isinstance(c, dict) and c.get("type") == "text":
                    texts.append(c.get("text", ""))
    return "\n".join(texts)

def smoke(port, label, timeout_s=150):
    st, parsed = rpc(port, "session/create", {"request": {"cwd": "/Users/zero/DSH_Work"}})
    if st != 200 or not parsed.get("result", {}).get("ok"):
        return f"FAIL {label}: create failed (HTTP {st})"
    sid = parsed["result"]["value"]["sessionId"]
    st, parsed = rpc(port, "session/prompt", {"request": {
        "requestId": f"smoke-{sid[-6:]}", "sessionId": sid, "mode": "queue",
        "content": [{"type": "text", "text": "调用 tm_status 工具查看门控状态，只需输出结果"}],
        "clientTimeZone": "Asia/Shanghai"}})
    if st != 200 or not parsed.get("result", {}).get("ok"):
        return f"FAIL {label}: prompt rejected (HTTP {st})"
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        out = read_v4(sid)
        if "TM_STATUS_CALLED" in out and ("HEALTHY" in out or "TM-Guard Status" in out):
            healthy = "HEALTHY" in out
            protected = "protected" in out.lower()
            return (f"PASS {label} (port {port}, {sid}): tm_status called, "
                    f"health={'HEALTHY' if healthy else 'MISSING'}, "
                    f"workspace-protected={'yes' if protected else 'NO'}")
        time.sleep(8)
    return f"FAIL {label}: timeout, last output: {out[-200:] if out else '(empty)'}"

if __name__ == "__main__":
    matrix = [(3091, "dsh-0.1.2-rc.1"), (3111, "dsh-0.1.7-rc.2"), (3112, "dsh-0.2.0-rc.1")]
    results = [smoke(p, l) for p, l in matrix]
    for r in results: print(r)
    print("ALL PASS" if all(r.startswith("PASS") for r in results) else "SOME FAILED")
