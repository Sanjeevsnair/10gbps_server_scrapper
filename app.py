# app.py — Browserless extractor (GET only, robust multi-hop + JS hooks)
import asyncio, base64, html, os, re, time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, parse_qs, urljoin, unquote

import httpx
from flask import Flask, jsonify, request
from flask_cors import CORS
from selectolax.parser import HTMLParser
import quickjs

TARGET_HOST = "video-downloads.googleusercontent.com"
GOOG_RE = re.compile(r"https?://[^\s'\"<>]*" + re.escape(TARGET_HOST) + r"[^\s'\"<>]*")
DEFAULT_TIMEOUT = float(os.getenv("EXTRACT_TIMEOUT_SEC", "300"))

UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
HEADERS = {
    "user-agent": UA,
    "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "accept-language": "en-US,en;q=0.7",
    "cache-control": "no-cache",
    "pragma": "no-cache",
    "upgrade-insecure-requests": "1",
}

# ----------------- helpers -----------------
def _maybe_decode_base64(s: str) -> Optional[str]:
    try:
        pad = '=' * (-len(s) % 4)
        return base64.b64decode(s + pad, validate=False).decode("utf-8","ignore")
    except Exception:
        return None

def _maybe_decode_hex(s: str) -> Optional[str]:
    try:
        if re.fullmatch(r"[0-9a-fA-F]+", s) and len(s) % 2 == 0:
            return bytes.fromhex(s).decode("utf-8","ignore")
    except Exception:
        pass
    return None

def _strip_gamerxyt_wrapper(u: str) -> str:
    try:
        p = urlparse(u)
        if p.netloc in ("gamerxyt.com","www.gamerxyt.com") and p.path == "/dl.php":
            link = (parse_qs(p.query).get("link") or [None])[0]
            if link:
                return html.unescape(unquote(link))
    except Exception:
        pass
    return u

def _extract_from_attrs(node) -> Optional[str]:
    for attr in ("href","data-href","data-url","data-download","data-link","onclick"):
        v = node.attributes.get(attr) or ""
        if not v:
            continue
        m = GOOG_RE.search(v)
        if m:
            return html.unescape(m.group(0))
        if "link=" in v:
            q = parse_qs(urlparse(v).query)
            link = html.unescape(unquote((q.get("link") or [""])[0]))
            if TARGET_HOST in link:
                return link
    return None

def _extract_direct_from_html(base: str, html_text: str) -> Optional[str]:
    m = GOOG_RE.search(html_text)
    if m:
        return html.unescape(m.group(0))
    tree = HTMLParser(html_text)

    for mnode in tree.css("meta[http-equiv]"):
        if (mnode.attributes.get("http-equiv") or "").lower() == "refresh":
            content = mnode.attributes.get("content") or ""
            m2 = re.search(r"url=([^;]+)", content, flags=re.I)
            if m2:
                u = urljoin(base, html.unescape(unquote(m2.group(1))).strip())
                if TARGET_HOST in u:
                    return u

    for sel in ("a","button"):
        for node in tree.css(sel):
            u = _extract_from_attrs(node);
            if u: return u

    for node in tree.css("[id*=download], [class*=download], [onclick]"):
        u = _extract_from_attrs(node)
        if u: return u

    for a in tree.css("a[href]"):
        href = a.attributes.get("href") or ""
        if "link=" in href:
            q = parse_qs(urlparse(href).query)
            link = html.unescape(unquote((q.get("link") or [""])[0]))
            if TARGET_HOST in link:
                return link
    return None

def _extract_from_scripts(html_text: str) -> Optional[str]:
    # 1) direct
    m = GOOG_RE.search(html_text)
    if m:
        return html.unescape(m.group(0))
    # 2) base64/hex blobs
    for b64tok in re.findall(r"[A-Za-z0-9+/=]{40,}", html_text):
        dec = _maybe_decode_base64(b64tok)
        if dec and TARGET_HOST in dec:
            return dec
    for hextok in re.findall(r"\b[0-9a-fA-F]{40,}\b", html_text):
        dec = _maybe_decode_hex(hextok)
        if dec and TARGET_HOST in dec:
            return dec
    # 3) atob("...")
    for m in re.finditer(r"atob\(\s*['\"]([A-Za-z0-9+/=]{8,})['\"]\s*\)", html_text):
        dec = _maybe_decode_base64(m.group(1))
        if dec and TARGET_HOST in dec:
            return dec
    return None

def _run_scripts_capture(html_text: str) -> Optional[str]:
    """
    Execute small <script> bodies in a sandbox and capture navigation/url emissions.
    Hooks: location.href/assign/replace, window.open, document.write.
    """
    scripts = re.findall(r"<script[^>]*>(.*?)</script>", html_text, flags=re.S|re.I)
    if not scripts:
        return None

    captured = {"val": None}
    def set_cap(v):
        if isinstance(v, str) and TARGET_HOST in v and not captured["val"]:
            captured["val"] = v
        return True

    ctx = quickjs.Context()
    try:
        ctx.add_callable("py_atob", lambda s: base64.b64decode(s).decode("utf-8","ignore"))
        ctx.add_callable("py_emit", lambda s: set_cap(s) or True)
        ctx.eval("""
            var __cap = function(v){ try { py_emit(String(v)); } catch(e){} };
            var atob = py_atob;
            var btoa = function(s){ return ""; };
            var document = {
                write: function(s){ __cap(s); return true; },
                body: { innerHTML: "" }
            };
            var window = {
                open: function(u){ __cap(u); return null; },
                addEventListener: function(){},
                location: { href: "" }
            };
            var location = {
                set href(u){ __cap(u); },
                get href(){ return ""; },
                assign: function(u){ __cap(u); },
                replace: function(u){ __cap(u); }
            };
            var navigator = { userAgent: "Mozilla" };
            var XMLHttpRequest = function(){ return { open(){}, send(){}, onload:null, responseText:"" } };
            var fetch = function(u){ __cap(u); return Promise.resolve({text:()=>Promise.resolve("")}); };
            var setTimeout = function(fn){ try{ fn(); }catch(e){} };
            var setInterval = function(fn){ try{ fn(); }catch(e){} };
            var console = { log: function(){}, error: function(){}, warn: function(){} };
        """)
        for raw in scripts[:50]:
            if captured["val"]:
                break
            code = raw.strip()
            if len(code) > 4000:
                continue
            try:
                ctx.eval(code)
            except Exception:
                # fallback: regex for location/window.open in plain text
                pass
        if captured["val"]:
            # sometimes document.write emits HTML containing the URL
            m = GOOG_RE.search(captured["val"])
            if m:
                return m.group(0)
            return captured["val"]
    except Exception:
        return None
    return None

def _meta_iframes_sources(base_url: str, html_text: str) -> List[str]:
    out = []
    tree = HTMLParser(html_text)
    for ifr in tree.css("iframe[src]"):
        src = ifr.attributes.get("src") or ""
        if src:
            out.append(urljoin(base_url, src))
    return out[:8]

# ----------------- network -----------------
async def _fetch_text(client: httpx.AsyncClient, url: str, timeout_sec: float) -> Tuple[str, str, httpx.Response]:
    resp = await client.get(url, headers=HEADERS, timeout=timeout_sec, follow_redirects=False)
    loc = resp.headers.get("location") or resp.headers.get("Location") or ""
    if loc:
        loc_abs = urljoin(url, loc)
        if TARGET_HOST in loc_abs:
            return url, "", resp
    return url, resp.text or "", resp

async def _resolve(url: str, hard_timeout_sec: float) -> Dict[str, Any]:
    t0 = time.time()
    deadline = t0 + hard_timeout_sec
    debug: List[str] = []
    visited: set = set()
    found_url: Optional[str] = None
    found_by: Optional[str] = None

    limits = httpx.Limits(max_keepalive_connections=4, max_connections=8)
    timeout = httpx.Timeout(connect=10.0, read=25.0, write=20.0, pool=10.0)

    async with httpx.AsyncClient(limits=limits, timeout=timeout) as client:
        cur = url
        for hop in range(8):
            if time.time() > deadline:
                break
            if cur in visited:
                break
            visited.add(cur)

            base, text, resp = await _fetch_text(client, cur, min(30.0, hard_timeout_sec))
            debug.append(f"H{hop} GET {cur} -> {resp.status_code}")

            # 1) header redirect
            loc = resp.headers.get("location") or resp.headers.get("Location") or ""
            if loc:
                loc_abs = urljoin(base, loc)
                if TARGET_HOST in loc_abs:
                    found_url, found_by = loc_abs, "http_redirect"
                    break
                if resp.status_code in (301,302,303,307,308):
                    cur = loc_abs
                    continue

            # 2) direct DOM extraction
            direct = _extract_direct_from_html(base, text)
            if direct:
                found_url, found_by = direct, "dom"
                break

            # 3) plain script decoding
            s1 = _extract_from_scripts(text)
            if s1:
                found_url, found_by = s1, "script_decode"
                break

            # 4) execute scripts with hooks
            s2 = _run_scripts_capture(text)
            if s2:
                found_url, found_by = s2, "script_exec"
                break

            # 5) ?link= on current URL
            q = parse_qs(urlparse(cur).query)
            lp = (q.get("link") or [""])[0]
            if lp and TARGET_HOST in lp:
                found_url, found_by = html.unescape(unquote(lp)), "link_param_on_url"
                break

            # 6) iframes (shallow)
            for src in _meta_iframes_sources(base, text):
                if time.time() > deadline:
                    break
                try:
                    _, if_text, if_resp = await _fetch_text(client, src, min(20.0, hard_timeout_sec))
                    debug.append(f"H{hop} IFRAME {src} -> {if_resp.status_code}")
                    loc2 = if_resp.headers.get("location") or ""
                    if loc2:
                        loc2_abs = urljoin(src, loc2)
                        if TARGET_HOST in loc2_abs:
                            found_url, found_by = loc2_abs, "iframe_redirect"
                            break
                    d2 = _extract_direct_from_html(src, if_text)
                    if d2:
                        found_url, found_by = d2, "iframe_dom"
                        break
                    s3 = _extract_from_scripts(if_text) or _run_scripts_capture(if_text)
                    if s3:
                        found_url, found_by = s3, "iframe_script"
                        break
                except Exception as e:
                    debug.append(f"H{hop} IFRAME_FAIL {src}: {type(e).__name__}")
            if found_url:
                break

            # 7) heuristic ajax endpoints
            for m in re.finditer(r"""['"](/[^'"]{0,160}(?:dl|get|resolve|api)[^'"]*)['"]""", text, flags=re.I):
                ajax_path = urljoin(base, m.group(1))
                if ajax_path in visited:
                    continue
                try:
                    r = await client.get(ajax_path, headers=HEADERS, timeout=20.0, follow_redirects=True)
                    debug.append(f"H{hop} AJAX {ajax_path} -> {r.status_code}")
                    if TARGET_HOST in r.text:
                        mm = GOOG_RE.search(r.text)
                        if mm:
                            found_url, found_by = html.unescape(mm.group(0)), "ajax_body"
                            break
                    if TARGET_HOST in str(r.url):
                        found_url, found_by = str(r.url), "ajax_redirect"
                        break
                    q2 = parse_qs(urlparse(str(r.url)).query)
                    lp2 = (q2.get("link") or [""])[0]
                    if lp2 and TARGET_HOST in lp2:
                        found_url, found_by = html.unescape(unquote(lp2)), "ajax_link_param"
                        break
                except Exception as e:
                    debug.append(f"H{hop} AJAX_FAIL {ajax_path}: {type(e).__name__}")
            if found_url:
                break

            # bail if nothing new to try this hop
            break

    if not found_url:
        raise RuntimeError("No direct link found without a browser (site may require JS runtime with DOM or anti-bot).")

    found_url = _strip_gamerxyt_wrapper(found_url)

    return {
        "ok": True,
        "url": found_url,
        "found_by": found_by,
        "host": TARGET_HOST,
        "elapsed_ms": int((time.time() - t0) * 1000),
        "debug": debug,
    }

# ----------------- flask -----------------
app = Flask("10Gbps Resolver (Browserless)")
CORS(app, supports_credentials=False)

@app.get("/resolve-10gbps")
def resolve_get():
    url = request.args.get("url", type=str)
    timeout_sec = request.args.get("timeout_sec", default=DEFAULT_TIMEOUT, type=float)

    if not url:
        return jsonify({"ok": False, "error": "Missing ?url parameter"}), 400
    if not (5.0 <= timeout_sec <= 600.0):
        return jsonify({"ok": False, "error": "timeout_sec must be between 5.0 and 600.0"}), 400

    t0 = time.time()
    try:
        res = asyncio.run(asyncio.wait_for(_resolve(url, hard_timeout_sec=timeout_sec), timeout=timeout_sec + 5.0))
        res["total_elapsed_ms"] = int((time.time() - t0) * 1000)
        res["vendor"] = "10Gbps Server"
        return jsonify(res)
    except asyncio.TimeoutError:
        return jsonify({"ok": False, "error": "Timed out in browserless resolver."}), 504
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT","7860")), debug=False)
