#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base64
import json
import logging
import os
import re
import tempfile
import time
import concurrent.futures
from collections import defaultdict
from typing import Dict, List, Optional
from urllib.parse import urljoin, urlparse, urlunparse, urlencode

import requests
from bs4 import BeautifulSoup
from fastapi import FastAPI, HTTPException, Body, Query
from pydantic import BaseModel
import uvicorn

# =====================================================================
# Logging
# =====================================================================

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("lumino")

# =====================================================================
# Config
# =====================================================================

headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                  "AppleWebKit/537.36 (KHTML, like Gecko) "
                  "Chrome/141.0.0.0 Safari/537.36"
}

DOMAINS_URL = "https://raw.githubusercontent.com/phisher98/TVVVV/refs/heads/main/domains.json"
DEFAULT_4KHDHUB = "https://4khdhub.fans"
MOVIESDRIVE_BASE = "https://moviesdrive.mom"

# Cache dir (for screenshots/logs if needed)
def get_cache_dir():
    try:
        cache_dir = os.path.expanduser('~/.cache/lumino')
        os.makedirs(cache_dir, exist_ok=True)
        if os.access(cache_dir, os.W_OK):
            return cache_dir
    except Exception as e:
        logger.warning(f"Home cache unusable: {e}")
    try:
        cache_dir = os.path.join(tempfile.gettempdir(), 'lumino')
        os.makedirs(cache_dir, exist_ok=True)
        if os.access(cache_dir, os.W_OK):
            return cache_dir
    except Exception as e:
        logger.warning(f"Temp cache unusable: {e}")
    return "/tmp"

CACHE_DIR = get_cache_dir()

# =====================================================================
# HTTP helpers
# =====================================================================

_SESSION = requests.Session()
_SESSION.headers.update(headers)
_DEFAULT_TIMEOUT = 15

def http_get(url: str, referer: Optional[str] = None, allow_redirects: bool = True, timeout: int = _DEFAULT_TIMEOUT) -> requests.Response:
    req_headers = dict(headers)
    if referer:
        req_headers["Referer"] = referer
    resp = _SESSION.get(url, headers=req_headers, allow_redirects=allow_redirects, timeout=timeout)
    resp.raise_for_status()
    return resp

def http_head(url: str, referer: Optional[str] = None, allow_redirects: bool = True, timeout: int = 10) -> requests.Response:
    req_headers = dict(headers)
    if referer:
        req_headers["Referer"] = referer
    resp = _SESSION.head(url, headers=req_headers, allow_redirects=allow_redirects, timeout=timeout)
    resp.raise_for_status()
    return resp

def abs_url(base: str, url: str) -> str:
    if not url:
        return ""
    if url.startswith("//"):
        return "https:" + url
    if url.lower().startswith("http"):
        return url
    return urljoin(base, url)

def is_valid_url(url: str) -> bool:
    try:
        u = urlparse(url)
        return bool(u.scheme and u.netloc)
    except Exception:
        return False

# =====================================================================
# Domains discovery (4KHDHub main URL)
# =====================================================================

def get_domains() -> Dict:
    try:
        resp = http_get(DOMAINS_URL)
        return resp.json()
    except Exception as e:
        logger.warning(f"Failed to fetch domains.json: {e}")
        return {}

domains = get_domains()
FOURK_MAIN = domains.get("4khdhub") or domains.get("n4khdhub") or DEFAULT_4KHDHUB
logger.info(f"Using 4KHDHub base: {FOURK_MAIN}")

# =====================================================================
# Utilities for parsing page sizes / qualities / titles
# =====================================================================

def parse_size_to_gb(size_str: Optional[str]) -> float:
    if not size_str:
        return float("inf")
    s = size_str.strip()
    m = re.search(r"(\d+(?:\.\d+)?)\s*(GB|MB)", s, re.I)
    if not m:
        return float("inf")
    num = float(m.group(1))
    unit = m.group(2).upper()
    return num if unit == "GB" else num / 1024.0

def clean_title(title: str) -> str:
    parts = re.split(r"[.\-_]", title or "")
    quality_tags = ["WEBRip", "WEB-DL", "WEB", "BluRay", "HDRip", "DVDRip", "HDTV", "CAM", "TS", "R5", "DVDScr", "BRRip", "BDRip", "DVD", "PDTV", "HD"]
    audio_tags   = ["AAC", "AC3", "DTS", "MP3", "FLAC", "DD5", "EAC3", "Atmos"]
    sub_tags     = ["ESub", "ESubs", "Subs", "MultiSub", "NoSub", "EnglishSub", "HindiSub"]
    codec_tags   = ["x264", "x265", "H264", "HEVC", "AVC"]

    start = next((i for i, p in enumerate(parts) if any(tag.lower() in p.lower() for tag in quality_tags)), -1)
    end   = next((i for i, p in enumerate(parts) if any(tag.lower() in p.lower() for tag in (sub_tags + audio_tags + codec_tags))), -1)
    if start != -1 and end != -1 and end >= start:
        return ".".join(parts[start:end+1])
    elif start != -1:
        return ".".join(parts[start:])
    else:
        return ".".join(parts[-3:]) if parts else ""

def get_index_quality_int(text: str) -> int:
    m = re.search(r"(\d{3,4})[pP]", text or "")
    if m:
        try:
            return int(m.group(1))
        except:
            pass
    return 2160

# =====================================================================
# New mediator decoder (ported from your Kotlin getRedirectLinks)
# =====================================================================

_MEDIATOR_REGEX = re.compile(r"s\('o','([A-Za-z0-9+/=]+)'|ck\('_wp_http_\d+','([^']+)'", re.I)

def _rot13(s: str) -> str:
    out = []
    for ch in s:
        o = ord(ch)
        if 65 <= o <= 90:   # A-Z
            out.append(chr((o - 65 + 13) % 26 + 65))
        elif 97 <= o <= 122:  # a-z
            out.append(chr((o - 97 + 13) % 26 + 97))
        else:
            out.append(ch)
    return "".join(out)

def _b64decode_str(s: str) -> str:
    # Gracefully handle padding issues
    try:
        padded = s + "=" * (-len(s) % 4)
        return base64.b64decode(padded).decode("utf-8", errors="ignore")
    except Exception:
        return ""

def mediator_get_redirect_links(url: str) -> str:
    """
    Fully replaces the old Selenium mediator flow.
    Mirrors Kotlin:
      - collect base64 tokens from s('o','...') | ck('_wp_http_x','...')
      - base64 decode twice, then ROT13, then base64 decode
      - parse JSON
      - try 'o' (base64 decoded) OR fetch blog_url?re=<decoded(data)>
    Returns final resolved link (may be hubdrive/hubcloud/others), or "" if failed.
    """
    try:
        resp_text = http_get(url).text
    except Exception as e:
        logger.error(f"[mediator] GET failed: {e}")
        return ""

    combined = []
    for m in _MEDIATOR_REGEX.finditer(resp_text):
        part = m.group(1) or m.group(2) or ""
        if part:
            combined.append(part)
    combined_str = "".join(combined).strip()
    if not combined_str:
        logger.warning("[mediator] No tokens matched; returning empty")
        return ""

    try:
        # decodedString = base64Decode( ROT13( base64Decode( base64Decode(combined) ) ) )
        step1 = _b64decode_str(combined_str)
        step2 = _b64decode_str(step1)
        step3 = _rot13(step2)
        decoded = _b64decode_str(step3)
        if not decoded:
            logger.warning("[mediator] Decoding pipeline produced empty result")
            return ""
        obj = json.loads(decoded)
    except Exception as e:
        logger.error(f"[mediator] Decode JSON failed: {e}")
        return ""

    try:
        encoded_o = obj.get("o", "") or ""
        final_url_from_o = _b64decode_str(encoded_o).strip() if encoded_o else ""
    except Exception:
        final_url_from_o = ""

    try:
        # Kotlin: data = Base64.decode(json.data)
        data_raw = obj.get("data", "") or ""
        data_decoded = base64.b64decode(data_raw + "=" * (-len(data_raw) % 4)).decode("utf-8", errors="ignore").strip() if data_raw else ""
    except Exception:
        data_decoded = ""

    blog_url = obj.get("blog_url", "") or ""
    direct_via_blog = ""
    if blog_url and data_decoded:
        try:
            # GET blog_url?re=<data_decoded> and use the body text
            q = urlencode({"re": data_decoded})
            blog_endpoint = blog_url + ("&" if "?" in blog_url else "?") + q
            direct_via_blog = http_get(blog_endpoint).text.strip()
        except Exception as e:
            logger.warning(f"[mediator] blog_url fetch failed: {e}")

    # Preference: decoded 'o' if present, else the blog direct text
    final = (final_url_from_o or direct_via_blog or "").strip()
    logger.info(f"[mediator] Resolved → {final[:120]}{'...' if len(final)>120 else ''}")
    return final

# =====================================================================
# 4KHDHub: search + load (page parsing)
# =====================================================================

def to_search_result(a: BeautifulSoup, base_url: str) -> Optional[Dict]:
    h3 = a.select_one("h3")
    if not h3:
        return None
    title = h3.get_text(strip=True)
    href = a.get("href") or ""
    if not href.startswith("http"):
        href = urljoin(base_url, href)
    img = a.select_one("img")
    poster = img.get("src") if img else None
    return {"title": title, "url": href, "poster": poster}

def search_4k(query: str) -> List[Dict]:
    url = f"{FOURK_MAIN}/?s={query}"
    try:
        soup = BeautifulSoup(http_get(url).text, "html.parser")
        results = []
        for a in soup.select("div.card-grid a"):
            r = to_search_result(a, FOURK_MAIN)
            if r:
                results.append(r)
        return results
    except Exception as e:
        logger.error(f"[search_4k] failed: {e}")
        return []

def load_4k(url: str) -> Dict:
    """
    Return dict with either Movie or TvSeries schema similar to your previous code:
    - Movie: variants (quality/size/links/filename)
    - TvSeries: episodes[season][episode] -> list of variants
    """
    try:
        soup = BeautifulSoup(http_get(url).text, "html.parser")
    except Exception as e:
        logger.error(f"[load_4k] GET failed: {e}")
        return {}

    title_elem = soup.select_one("h1.page-title")
    title = (title_elem.get_text(strip=True) if title_elem else "").split("(")[0].strip()

    poster = ""
    og = soup.select_one("meta[property='og:image']")
    if og and og.has_attr("content"):
        poster = og["content"]

    tags = [span.get_text(strip=True) for span in soup.select("div.mt-2 span.badge")]
    year = None
    for span in soup.select("div.mt-2 span"):
        text = span.get_text(strip=True)
        if re.match(r"^(19|20)\d{2}$", text):
            year = int(text)
            break

    tv_type = "Movie" if "Movies" in tags else "TvSeries"
    description = None
    desc = soup.select_one("div.content-section p.mt-4")
    if desc:
        description = desc.get_text(strip=True)

    if tv_type == "TvSeries":
        episode_variants = defaultdict(lambda: defaultdict(list))
        for season_elem in soup.select("div.episodes-list div.season-item"):
            season_text = season_elem.select_one("div.episode-number")
            season_text = season_text.get_text(strip=True) if season_text else ""
            m_season = re.search(r"S?([1-9][0-9]*)", season_text)
            if not m_season:
                continue
            season = int(m_season.group(1))

            for ep_item in season_elem.select("div.episode-download-item"):
                ep_text = ep_item.select_one("div.episode-file-info span.badge-psa")
                ep_text = ep_text.get_text(strip=True) if ep_text else ""
                m_ep = re.search(r"Episode-0*([1-9][0-9]*)", ep_text)
                if not m_ep:
                    continue
                episode = int(m_ep.group(1))

                hrefs = [a.get("href") for a in ep_item.select("a") if a.get("href")]
                size_elem = ep_item.select_one("div.episode-file-info span.badge-danger")
                size_text = size_elem.get_text(strip=True) if size_elem else None
                if not size_text:
                    size_match = re.search(r"(\d+(?:\.\d+)?\s*[GM]B)", ep_item.get_text())
                    size_text = size_match.group(1) if size_match else "Unknown"
                size_num = parse_size_to_gb(size_text)

                strings = list(ep_item.stripped_strings)
                filename_candidates = [s for s in strings if re.search(r"\.(mkv|mp4)$", s, re.I) and len(s) > 20]
                file_title = filename_candidates[0] if filename_candidates else ep_text
                file_title = re.sub(r"\[[^]]*\]", "", file_title)
                file_title = re.sub(r"\(.+?\)", "", file_title)

                m_q = re.search(r"(\d{3,4})[pP]", file_title)
                quality = int(m_q.group(1)) if m_q else 0

                episode_variants[season][episode].append({
                    "quality": quality,
                    "size": size_num,
                    "links": hrefs,
                    "filename": file_title
                })

        return {
            "type": "TvSeries",
            "title": title,
            "url": url,
            "episodes": {int(s): {int(e): v for e, v in eps.items()} for s, eps in episode_variants.items()},
            "poster": poster,
            "year": year,
            "plot": description,
            "tags": tags
        }
    else:
        variants = []
        for item in soup.select("div.download-item"):
            header_text = item.select_one("div.flex-1.text-left.font-semibold")
            header_text = header_text.get_text(strip=True) if header_text else ""
            m_sz = re.search(r"(\d+(?:\.\d+)?\s*GB)", header_text)
            size_text = m_sz.group(1) if m_sz else "Unknown"
            size_num = parse_size_to_gb(size_text)
            m_q = re.search(r"(\d{3,4})[pP]", header_text)
            quality = int(m_q.group(1)) if m_q else 0
            hrefs = [a.get("href") for a in item.select("a") if a.get("href")]
            file_title_elem = item.select_one("div.file-title")
            file_title = file_title_elem.get_text(strip=True) if file_title_elem else ""
            file_title = re.sub(r"\[[^]]*\]", "", file_title)
            file_title = re.sub(r"\(.+?\)", "", file_title)
            variants.append({
                "quality": quality,
                "size": size_num,
                "links": hrefs,
                "filename": file_title
            })

        return {
            "type": "Movie",
            "title": title,
            "url": url,
            "variants": variants,
            "poster": poster,
            "year": year,
            "plot": description,
            "tags": tags
        }

# =====================================================================
# Link collectors based on new mediator
# =====================================================================

def get_redirect_links(url: str) -> str:
    """
    Single-link resolver — if mediator, decode; otherwise return url itself.
    """
    try:
        if "id=" in url.lower():
            return mediator_get_redirect_links(url)
        return url
    except Exception as e:
        logger.warning(f"[redirect] failed for {url}: {e}")
        return ""

def collect_links_from_variant(links_list: List[str], source_quality: int = 0) -> List[Dict]:
    """
    Given the list of strings/hrefs for a variant, normalize/resolve them.
    Returns a list of dicts with name/url/quality.
    """
    results = []
    for link_str in links_list:
        # Find all URLs in the string
        urls = re.findall(r'https?://[^\s\'",()\[\]]+', link_str) or [link_str]
        for u in urls:
            u = u.strip()
            if not is_valid_url(u):
                continue
            resolved = get_redirect_links(u)
            final = resolved if resolved else u
            low = (final or "").lower()
            if "hubdrive" in low:
                results.append({"name": "HUB Drive", "url": final, "quality": source_quality})
            elif "hubcloud" in low:
                results.append({"name": "Hub Cloud", "url": final, "quality": source_quality})
            else:
                results.append({"name": "Direct", "url": final, "quality": source_quality})
    return results

def select_lowest_size_per_quality(variants: List[Dict]) -> List[Dict]:
    if not variants:
        return []
    groups = defaultdict(list)
    for v in variants:
        groups[v.get("quality", 0)].append(v)
    selected = []
    for q, vs in groups.items():
        min_v = min(vs, key=lambda x: x.get("size", float("inf")))
        selected.append(min_v)
    return sorted(selected, key=lambda x: x.get("quality", 0), reverse=True)

from urllib.parse import urlparse, urljoin, parse_qs, unquote

def _extract_link_param(u: str) -> Optional[str]:
    try:
        parsed = urlparse(u)
        qs = parse_qs(parsed.query)
        if "link" in qs and qs["link"]:
            return unquote(qs["link"][0])
        # allow cases like ...link=<url> without '?'
        m = re.search(r"[?&]link=([^&]+)", u)
        if m:
            return unquote(m.group(1))
    except Exception:
        pass
    return None

def _resolve_10gbps(start_url: str, referer: Optional[str], max_hops: int = 8) -> Optional[str]:
    """
    Follow a few 302s manually until we see a URL with link= param,
    or extract from HTML if available. Never raises; returns None on failure.
    """
    current = start_url
    base_for_rel = get_base_url(start_url)
    headers_local = dict(headers)
    if referer:
        headers_local["Referer"] = referer

    # 1) If the start url already contains link=, decode and return
    direct = _extract_link_param(current)
    if direct:
        return direct

    for _ in range(max_hops):
        try:
            r = _SESSION.get(current, headers=headers_local, allow_redirects=False, timeout=10)
        except Exception:
            # DNS / network failure -> try HTML parse fallback once
            try:
                r2 = _SESSION.get(current, headers=headers_local, allow_redirects=True, timeout=10)
                html = r2.text
                # meta refresh
                m = re.search(r'<meta[^>]+http-equiv=["\']refresh["\'][^>]+url=([^"\'>]+)', html, re.I)
                if m:
                    nxt = m.group(1).strip()
                    if not nxt.lower().startswith("http"):
                        nxt = urljoin(current, nxt)
                    got = _extract_link_param(nxt)
                    if got:
                        return got
                    current = nxt
                    continue
                # direct anchor to link=
                a = re.search(r'href=["\']([^"\']+link=[^"\']+)["\']', html, re.I)
                if a:
                    nxt = a.group(1)
                    if not nxt.lower().startswith("http"):
                        nxt = urljoin(current, nxt)
                    got = _extract_link_param(nxt)
                    if got:
                        return got
                    current = nxt
                    continue
            except Exception:
                pass
            return None

        loc = r.headers.get("location") or r.headers.get("Location")
        if not loc:
            break

        # If we already got link=, decode and finish
        got = _extract_link_param(loc)
        if got:
            return got

        # normalise relative redirects
        if not loc.lower().startswith("http"):
            loc = urljoin(get_base_url(current) + "/", loc.lstrip("/"))

        current = loc

    # One last HTML try if we exited loop without success
    try:
        r3 = _SESSION.get(current, headers=headers_local, allow_redirects=True, timeout=10)
        html = r3.text
        a = re.search(r'href=["\']([^"\']+link=[^"\']+)["\']', html, re.I)
        if a:
            candidate = a.group(1)
            if not candidate.lower().startswith("http"):
                candidate = urljoin(current, candidate)
            got = _extract_link_param(candidate)
            if got:
                return got
    except Exception:
        pass

    return None


# =====================================================================
# HubDrive & HubCloud extractors (requests-based)
# =====================================================================

def hubdrive_extract(url: str) -> List[Dict]:
    """
    Equivalent to Kotlin Hubdrive.getUrl:
    - Load the page, find the .btn.btn-primary.btn-user.btn-success1.m-1 href
    - If it contains hubcloud => delegate to hubcloud
    - Else return direct link entry
    """
    out = []
    try:
        doc = BeautifulSoup(http_get(url).text, "html.parser")
        href = doc.select_one(".btn.btn-primary.btn-user.btn-success1.m-1")
        href = href.get("href") if href and href.has_attr("href") else ""
        if not href:
            logger.warning(f"[hubdrive] No primary href found on {url}")
            return out

        if "hubcloud" in href.lower():
            out.extend(hubcloud_extract(href))
        else:
            out.append({
                "server": "Direct",
                "quality": None,
                "url": href,
                "label": ""
            })
        return out
    except Exception as e:
        logger.error(f"[hubdrive] ERROR {e}")
        return out

def _hubcloud_get_download_href(real_url: str) -> str:
    """
    Kotlin logic:
      - if "hubcloud.php" in URL => use as-is
      - else GET page and read #download href
      - make absolute to the same base
    """
    if "hubcloud.php" in real_url:
        return real_url
    base = get_base_url(real_url)
    try:
        doc = BeautifulSoup(http_get(real_url).text, "html.parser")
        raw = doc.select_one("#download")
        href = raw.get("href") if raw and raw.has_attr("href") else ""
        if href and not href.lower().startswith("http"):
            href = base.rstrip("/") + "/" + href.lstrip("/")
        return href or ""
    except Exception as e:
        logger.error(f"[hubcloud] Failed to grab #download on {real_url}: {e}")
        return ""

def get_base_url(url: str) -> str:
    try:
        u = urlparse(url)
        return f"{u.scheme}://{u.netloc}"
    except Exception:
        return ""

def hubcloud_extract(url: str) -> List[Dict]:
    """
    Mirrors Kotlin HubCloud.getUrl:
      - normalize to download page
      - parse header & size for labels
      - iterate buttons inside "div.card-body h2 a.btn"
      - handle FSL, Download File, BuzzServer (hx-redirect), Pixeldrain, S3, 10Gbps redirect chain
    """
    results = []
    real_url = url.strip()
    if not is_valid_url(real_url):
        logger.warning(f"[hubcloud] Invalid URL: {real_url}")
        return results

    href = _hubcloud_get_download_href(real_url)
    if not href:
        logger.warning("[hubcloud] No valid href on first page")
        return results

    try:
        doc = BeautifulSoup(http_get(href).text, "html.parser")
    except Exception as e:
        logger.error(f"[hubcloud] GET href failed: {e}")
        return results

    size = ""
    size_el = doc.select_one("i#size")
    if size_el:
        size = size_el.get_text(strip=True)
    header = ""
    header_el = doc.select_one("div.card-header")
    if header_el:
        header = header_el.get_text(strip=True)

    header_details = clean_title(header)
    label_extras = ""
    if header_details:
        label_extras += f"[{header_details}]"
    if size:
        label_extras += f"[{size}]"
    quality = get_index_quality_int(header)

    # buttons
    buttons = doc.select("div.card-body h2 a.btn")
    logger.info(f"[hubcloud] Found {len(buttons)} buttons")
    base = get_base_url(href)

    for btn in buttons:
        text = btn.get_text(strip=True)
        link = btn.get("href") or ""
        if not link:
            continue

        low = text.lower()
        if "fsl server" in low:
            results.append({
                "server": "FSL Server",
                "quality": quality,
                "url": link,
                "label": label_extras
            })
        elif "download file" in low:
            results.append({
                "server": "Direct",
                "quality": quality,
                "url": link,
                "label": label_extras
            })
        elif "buzzserver" in low:
            try:
                # GET $link/download with referer=link, allow_redirects=False => header hx-redirect
                r = http_get(urljoin(link, "download"), referer=link, allow_redirects=False)
                dlink = r.headers.get("hx-redirect", "") or r.headers.get("HX-Redirect", "") or ""
                if dlink:
                    if not dlink.lower().startswith("http"):
                        dlink = base.rstrip("/") + "/" + dlink.lstrip("/")
                    results.append({
                        "server": "BuzzServer",
                        "quality": quality,
                        "url": dlink,
                        "label": label_extras
                    })
                else:
                    logger.warning("[hubcloud] BuzzServer: No hx-redirect")
            except Exception as e:
                logger.warning(f"[hubcloud] BuzzServer failed: {e}")
        elif "pixel" in low:
            results.append({
                "server": "Pixeldrain",
                "quality": quality,
                "url": link,
                "label": label_extras
            })
        elif "s3 server" in low:
            results.append({
                "server": "S3 Server",
                "quality": quality,
                "url": link,
                "label": label_extras
            })
        elif "10gbps" in low:
            # robust extraction of the ultimate ?link= target; survive DNS issues
            final = _extract_link_param(link)
            if not final:
                final = _resolve_10gbps(link, referer=href)
            if final:
                results.append({
            "server": "10Gbps Server",
            "quality": quality,
            "url": final,
            "label": label_extras
            })
            else:
            # return the original button so clients can resolve under a working DNS
                results.append({
            "server": "10Gbps Server (unresolved)",
            "quality": quality,
            "url": link,
            "label": label_extras + "[dns-fallback]"
            })
        else:
            # Unknown server — still return it
            results.append({
                "server": "Unknown Server",
                "quality": quality,
                "url": link,
                "label": label_extras
            })

    return results

# =====================================================================
# MoviesDrive: search + resolve (kept as in your previous design)
# =====================================================================

def fetch_soup(url: str, timeout: int = 15) -> Optional[BeautifulSoup]:
    try:
        r = http_get(url, timeout=timeout)
        return BeautifulSoup(r.text, "html.parser")
    except Exception as e:
        logger.warning(f"[fetch_soup] Error fetching {url}: {e}")
        return None

def searchx(query: str, max_pages: int = 5) -> List[Dict]:
    results = []
    for page in range(1, max_pages + 1):
        url = f"{MOVIESDRIVE_BASE}/page/{page}/?s={requests.utils.requote_uri(query)}"
        soup = fetch_soup(url)
        if not soup:
            break
        items = soup.select("ul.recent-movies > li")
        if not items:
            break
        for li in items:
            try:
                img = li.select_one("figure > img")
                a = li.select_one("figure > a")
                title = (img.get("title") or "").replace("Download ", "").strip()
                href = a.get("href") if a else None
                poster = img.get("src") if img else None
                quality = None
                if title and ("HDCAM" in title.upper() or "CAMRIP" in title.upper()):
                    quality = "CAM"
                if href:
                    results.append({
                        "title": title,
                        "url": href,
                        "poster": poster,
                        "quality": quality
                    })
            except Exception:
                continue
    return results

def fast_resolve(url: str) -> Optional[str]:
    try:
        if url.startswith("//"):
            url = "https:" + url
        if not url.startswith("http"):
            url = "https://" + url.lstrip("/")

        if "pixeldrain.dev/u/" in url:
            m = re.search(r"/u/([A-Za-z0-9]+)", url)
            if m:
                file_id = m.group(1)
                return f"https://pixeldrain.dev/api/file/{file_id}?download"

        if "drive.google.com" in url:
            m = re.search(r"/d/([^/]+)/", url)
            if m:
                file_id = m.group(1)
                return f"https://drive.google.com/uc?id={file_id}&export=download"

        r = http_get(url)
        html = r.text

        m_media = re.search(r'(https?://[^\s"\']+\.(?:mp4|m3u8)(?:\?[^"\']*)?)', html, re.I)
        if m_media:
            return m_media.group(1)

        m_iframe = re.search(r'<iframe[^>]+src=["\']([^"\']+)["\']', html, re.I)
        if m_iframe:
            return urljoin(url, m_iframe.group(1))

        m_js = re.search(r'file\s*[:=]\s*["\'](https?://[^"\']+)["\']', html, re.I)
        if m_js:
            return m_js.group(1)

    except Exception as e:
        logger.warning(f"[fast_resolve] failed {url}: {e}")
    return None

def resolve_all(video_pages: List[str], max_workers: int = 8) -> List[str]:
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(fast_resolve, vp): vp for vp in video_pages}
        for f in concurrent.futures.as_completed(futures):
            res = f.result()
            if res and res not in results:
                results.append(res)
    return results

def extract_sub_links(page_url: str) -> List[str]:
    links = []
    try:
        soup = fetch_soup(page_url)
        if not soup:
            return links
        for a in soup.find_all("a", href=True):
            href = a["href"]
            if re.search(r"(hubcloud|gdflix|pixeldrain|drive\.google|embed|cloud)", href, re.I):
                links.append(href)
        for iframe in soup.find_all("iframe", src=True):
            src = iframe["src"]
            links.append(src)
    except Exception as e:
        logger.warning(f"[extract_sub_links] failed {page_url}: {e}")
    # dedupe
    out = []
    for l in links:
        if l not in out:
            out.append(l)
    return out

def get_video_metadata(url: str) -> Dict:
    meta = {"url": url, "resolution": None, "audio": None, "info": None}
    m_res = re.search(r"(\d{3,4}p)", url, re.I)
    if m_res:
        meta["resolution"] = m_res.group(1)
    if "pixeldrain.dev/api/file/" in url:
        try:
            r = http_head(url, allow_redirects=True)
            size = r.headers.get("Content-Length")
            meta["info"] = f"Size: {size} bytes" if size else None
            filename = r.headers.get("Content-Disposition", "")
            m_res2 = re.search(r"(\d{3,4}p)", filename or "")
            if m_res2:
                meta["resolution"] = m_res2.group(1)
        except Exception:
            pass
    return meta

def load_item(url: str) -> Dict:
    result = {"title": None, "poster": None, "description": None,
              "video_pages": [], "video_links": []}

    soup = fetch_soup(url)
    if not soup:
        return result

    og_title = soup.select_one("meta[property='og:title']")
    if og_title and og_title.has_attr("content"):
        result["title"] = og_title["content"].replace("Download ", "").strip()

    img = soup.select_one("img[decoding='async']")
    if img and img.has_attr("src"):
        result["poster"] = img["src"]

    storyline_node = None
    for header_tag in soup.find_all(["h2", "h3", "h4", "h5"]):
        if "storyline" in header_tag.get_text(strip=True).lower():
            storyline_node = header_tag.find_next_sibling()
            break
    if storyline_node:
        result["description"] = storyline_node.get_text(strip=True)

    video_pages = []
    try:
        buttons = soup.select("h5 a")
        for b in buttons:
            href = b.get("href")
            if href:
                video_pages.append(href)
    except Exception:
        pass

    if not video_pages:
        try:
            res_links = soup.find_all("a", string=re.compile(r'\d{3,4}p'))
            for link in res_links:
                href = link.get("href")
                if href:
                    video_pages.append(href)
            if not video_pages:
                buttons = soup.select("h4 a")
                for b in buttons:
                    href = b.get("href")
                    if href:
                        video_pages.append(href)
        except Exception:
            pass

    unique_video_pages = []
    for vp in video_pages:
        if vp.startswith("//"):
            vp = "https:" + vp
        if not vp.startswith("http"):
            vp = urljoin(url, vp)
        if vp not in unique_video_pages:
            unique_video_pages.append(vp)
    result["video_pages"] = unique_video_pages

    expanded_pages = []
    for vp in unique_video_pages:
        subs = extract_sub_links(vp)
        if subs:
            expanded_pages.extend(subs)
        else:
            expanded_pages.append(vp)
    # dedupe while keeping order
    seen = set()
    expanded_unique = []
    for l in expanded_pages:
        if l not in seen:
            expanded_unique.append(l)
            seen.add(l)

    resolved_links = resolve_all(expanded_unique)
    def rewrite_pixeldrain(link: str) -> str:
        m = re.search(r"/u/([A-Za-z0-9]+)", link)
        if m:
            file_id = m.group(1)
            return f"https://pixeldrain.dev/api/file/{file_id}?download"
        return link
    resolved_links = [rewrite_pixeldrain(l) for l in resolved_links]
    result["video_links"] = [get_video_metadata(l) for l in resolved_links]
    return result

# =====================================================================
# FastAPI models
# =====================================================================

class SearchRequest(BaseModel):
    query: str

class LinksRequest(BaseModel):
    url: str
    season: Optional[int] = None
    episode: Optional[int] = None

class HubDriveRequest(BaseModel):
    hubdrive_links: List[str]

class ExtractedLink(BaseModel):
    server: str
    url: str
    quality: Optional[int] = None
    label: Optional[str] = None

class ExtractedResponse(BaseModel):
    status: str
    total_links: int
    results: List[ExtractedLink]

# =====================================================================
# FastAPI app
# =====================================================================

app = FastAPI(title="Lumino API (No-Selenium)", description="4KHDHub + HubDrive/HubCloud + MoviesDrive")

@app.get("/")
async def root():
    return {"message": "Welcome to lumino API", "status": "running"}

@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "cache_dir": CACHE_DIR,
        "chromium_version": "not-used",
        "chromedriver_version": "not-used",
        "fourk_main": FOURK_MAIN
    }

# ---- 4KHDHub search ----
@app.post("/api/search")
async def api_search(request: SearchRequest):
    logger.info(f"[api_search] {request.query}")
    results = search_4k(request.query)
    if not results:
        raise HTTPException(status_code=404, detail="No results found")
    return {"results": results}

# ---- 4KHDHub get-links (collect hubdrive/hubcloud mediator-resolved links for a movie/episode) ----
@app.post("/api/get-links")
async def api_get_links(request: LinksRequest):
    if not request.url:
        raise HTTPException(status_code=400, detail="URL is required")

    logger.info(f"[api_get_links] {request.url}")
    data = load_4k(request.url)
    if not data:
        raise HTTPException(status_code=404, detail="Failed to load content")

    type_ = data["type"]
    title = data["title"]
    logger.info(f"Loaded: {title} ({type_})")

    metadata = {
        "title": title,
        "type": type_,
        "url": data["url"],
        "poster": data.get("poster", ""),
        "year": data.get("year"),
        "plot": data.get("plot", ""),
        "tags": data.get("tags", [])
    }

    # collect variants
    variants = []
    if type_ == "TvSeries":
        if request.season is None or request.episode is None:
            raise HTTPException(status_code=400, detail="Season and episode are required for TV series")
        season = request.season
        episode = request.episode
        variants = data["episodes"].get(season, {}).get(episode, [])
        if not variants:
            raise HTTPException(status_code=404, detail=f"Episode S{season:02d}E{episode:02d} not found")
        metadata["season"] = season
        metadata["episode"] = episode
        metadata["episode_name"] = f"S{season:02d}E{episode:02d}"
    else:
        if request.season is not None or request.episode is not None:
            raise HTTPException(status_code=400, detail="Season and episode should not be provided for movies")
        variants = data.get("variants", [])

    if not variants:
        raise HTTPException(status_code=404, detail="No variants found")

    selected = select_lowest_size_per_quality(variants)
    logger.info("Selected variants (lowest size per quality):")
    for sv in selected:
        size_gb = sv["size"] if sv["size"] != float("inf") else "Unknown"
        logger.info(f"- {sv['quality']}p [{size_gb} GB]: {sv['filename'][:100]}...")

    # Resolve and collect direct hubdrive/hubcloud links
    collected = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(5, len(selected) or 1)) as ex:
        futures = [ex.submit(collect_links_from_variant, sv["links"], sv["quality"]) for sv in selected]
        for f in concurrent.futures.as_completed(futures):
            try:
                collected.extend(f.result())
            except Exception as e:
                logger.warning(f"[collect] error: {e}")

    # Keep only hubdrive/hubcloud final links (like your previous behavior)
    filtered = []
    seen = set()
    for item in collected:
        url = item.get("url", "")
        if not url:
            continue
        low = url.lower()
        if "hubdrive" in low or "hubcloud" in low:
            if url not in seen:
                filtered.append(url)
                seen.add(url)

    logger.info(f"Extracted {len(filtered)}  hubdrive/hubcloud links")
    return {
        "metadata": metadata,
        "hubdrive_links": filtered
    }

# ---- Extract endpoint: from hubdrive/hubcloud to actual server links (FSL / Pixeldrain / etc.) ----
@app.post("/api/extract", response_model=ExtractedResponse)
def extract_links(req: HubDriveRequest):
    all_links = []
    for url in req.hubdrive_links:
        low = (url or "").lower()
        try:
            if "hubcloud" in low:
                all_links.extend(hubcloud_extract(url))
            elif "hubdrive" in low:
                all_links.extend(hubdrive_extract(url))
            else:
                # Not matched; try mediator decode if it's a mediator anyway
                resolved = get_redirect_links(url)
                if "hubcloud" in (resolved or "").lower():
                    all_links.extend(hubcloud_extract(resolved))
                elif "hubdrive" in (resolved or "").lower():
                    all_links.extend(hubdrive_extract(resolved))
        except Exception as e:
            logger.warning(f"[extract] failed for {url}: {e}")

    if not all_links:
        raise HTTPException(status_code=404, detail="No video links found.")
    return {"status": "success", "total_links": len(all_links), "results": all_links}

# ---- MoviesDrive endpoints ----
@app.get("/searchx")
def api_searchx(query: str = Query(..., description="Search term"),
                max_pages: int = Query(3, description="Max number of pages to scan")):
    results = searchx(query, max_pages=max_pages)
    if not results:
        raise HTTPException(status_code=404, detail="No results found.")
    return {"count": len(results), "results": results}

@app.get("/resolve")
def api_resolve(url: str = Query(..., description="Full moviesdrive.mom item URL")):
    if not url.startswith("http"):
        raise HTTPException(status_code=400, detail="Invalid URL.")
    data = load_item(url)
    if not data.get("video_links"):
        raise HTTPException(status_code=404, detail="No video links found.")
    return data

# =====================================================================
# Entrypoint
# =====================================================================

if __name__ == "__main__":
    logger.info("Starting 4KHDHub API (No-Selenium) on port 7860")
    uvicorn.run(app, host="0.0.0.0", port=7860, log_level="info")
