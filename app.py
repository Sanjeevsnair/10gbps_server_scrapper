#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base64
import binascii
import hashlib
import hmac
import json
import logging
import os
import re
import tempfile
import time
import math
import concurrent.futures
import threading
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import (
    urljoin,
    urlparse,
    urlunparse,
    urlencode,
    parse_qs,
    unquote,
    quote_plus,
)
from pathlib import Path
from contextlib import asynccontextmanager

import httpx
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from bs4 import BeautifulSoup
from fastapi import FastAPI, HTTPException, Query, status
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn
import unicodedata  # for accent-insensitive normalization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


# =====================================================================
# Logging
# =====================================================================

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("lumino")

CINEMAOS_API = "https://cinemaos.tech"
# From Kotlin (kept same)
GEN_HASH_S = "a8f7e9c2d4b6a1f3e8c9d2t4a7f6e9c2d4z6a1f3e8c9d2b4a7f5e9c2d4b6a1f3"


# =====================================================================
# Config (TUNED FOR SPEED) - UPDATED
# =====================================================================

FAST_EXTRACT_MODE = True  # True = no HEAD, much faster; False = include size_bytes/size_human

# Core per-request timeout (most calls)
_DEFAULT_TIMEOUT = 3

# Global retries on http_get (0 = no retries, fastest)
_MAX_RETRIES_GLOBAL = 1  # allow 1 retry for slight transient resilience

# Specific timeouts (in seconds)
SEARCH_TIMEOUT = 5          # search pages
HUB_TIMEOUT = 6             # hubdrive / hubcloud pages
MD_FAST_TIMEOUT = 6         # MoviesDrive md_fast_resolve (bumped from 3 -> 6)

# Limits to keep each request under control
MAX_VARIANTS_PER_ENTRY = 4  # per movie/episode, limit number of variants we expand
MAX_EXTRACT_LINKS = 12      # per /api/extract request, limit how many URLs we resolve

# HTTP headers
headers = {
    "User-Agent": (
        "Mozilla/55.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/141.0.0.0 Safari/537.36"
    )
}

DOMAINS_URL = "https://raw.githubusercontent.com/phisher98/TVVVV/refs/heads/main/domains.json"
DEFAULT_4KHDHUB = "https://4khdhub.fans"

MOVIESDRIVE_BASE = "https://moviesdrive.pics"


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
DOMAINS_CACHE_FILE = Path(CACHE_DIR) / "domains_cache.json"
DOMAINS_CACHE_TTL = 3600  # 1 hour

# =====================================================================
# HTTP helpers
# =====================================================================


def create_session_with_retry():
    session = requests.Session()

    # adapter retries = 0; we control retries in http_get via _MAX_RETRIES_GLOBAL
    retry_strategy = Retry(
        total=0,
        connect=0,
        read=0,
        redirect=0,
        backoff_factor=0,
        allowed_methods=["HEAD", "GET", "OPTIONS", "POST"]
    )

    adapter = HTTPAdapter(
        max_retries=retry_strategy,
        pool_connections=10,
        pool_maxsize=20
    )

    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.headers.update(headers)

    return session


_SESSION = create_session_with_retry()


def http_get(
    url: str,
    referer: Optional[str] = None,
    allow_redirects: bool = True,
    timeout: int = _DEFAULT_TIMEOUT,
    max_retries: int = _MAX_RETRIES_GLOBAL
) -> requests.Response:
    req_headers = dict(headers)
    if referer:
        req_headers["Referer"] = referer

    last_error = None
    for attempt in range(max_retries + 1):
        try:
            resp = _SESSION.get(
                url,
                headers=req_headers,
                allow_redirects=allow_redirects,
                timeout=timeout
            )
            resp.raise_for_status()
            return resp
        except requests.exceptions.Timeout as e:
            last_error = e
            logger.warning(f"Timeout on attempt {attempt + 1}/{max_retries + 1} for {url}")
            if attempt < max_retries:
                time.sleep(0.5 * (attempt + 1))
        except requests.exceptions.ConnectionError as e:
            last_error = e
            logger.warning(f"Connection error on attempt {attempt + 1}/{max_retries + 1} for {url}")
            if attempt < max_retries:
                time.sleep(0.5 * (attempt + 1))
        except requests.exceptions.HTTPError as e:
            if e.response.status_code < 500 and e.response.status_code != 429:
                raise
            last_error = e
            logger.warning(f"HTTP error {e.response.status_code} on attempt {attempt + 1}/{max_retries + 1}")
            if attempt < max_retries:
                time.sleep(0.5 * (attempt + 1))
        except Exception as e:
            last_error = e
            logger.error(f"Unexpected error on attempt {attempt + 1}/{max_retries + 1}: {e}")
            if attempt < max_retries:
                time.sleep(0.5 * (attempt + 1))

    raise last_error


def http_head(
    url: str,
    referer: Optional[str] = None,
    allow_redirects: bool = True,
    timeout: int = 5
) -> requests.Response:
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


def is_blocked_host(url: str) -> bool:
    low = (url or "").lower()
    blocked_keywords = [
        "t.me", "telegram.", "wa.me", "whatsapp.", "discord.gg", "discord.com"
    ]
    return any(b in low for b in blocked_keywords)

# =====================================================================
# Domains
# =====================================================================


def get_domains() -> Dict:
    if DOMAINS_CACHE_FILE.exists():
        try:
            cache_age = time.time() - DOMAINS_CACHE_FILE.stat().st_mtime
            if cache_age < DOMAINS_CACHE_TTL:
                with open(DOMAINS_CACHE_FILE, 'r') as f:
                    cached_domains = json.load(f)
                    logger.info(f"Using cached domains (age: {cache_age:.0f}s)")
                    return cached_domains
        except Exception as e:
            logger.warning(f"Failed to read domains cache: {e}")

    for attempt in range(3):
        try:
            resp = requests.get(DOMAINS_URL, headers=headers, timeout=5)
            resp.raise_for_status()
            domains_data = resp.json()

            try:
                with open(DOMAINS_CACHE_FILE, 'w') as f:
                    json.dump(domains_data, f)
                logger.info("Domains fetched and cached successfully")
            except Exception as e:
                logger.warning(f"Failed to cache domains: {e}")

            return domains_data

        except Exception as e:
            logger.warning(f"Attempt {attempt + 1}/3 to fetch domains failed: {e}")
            if attempt < 2:
                time.sleep(1 * (attempt + 1))

    if DOMAINS_CACHE_FILE.exists():
        try:
            with open(DOMAINS_CACHE_FILE, 'r') as f:
                stale_domains = json.load(f)
                logger.warning("Using stale cached domains as fallback")
                return stale_domains
        except Exception as e:
            logger.error(f"Failed to read stale cache: {e}")

    logger.error("All domain fetching methods failed, using hardcoded defaults")
    return {
        "4khdhub": DEFAULT_4KHDHUB
    }


domains = get_domains()
FOURK_MAIN = domains.get("4khdhub") or domains.get("n4khdhub") or DEFAULT_4KHDHUB
logger.info(f"Using 4KHDHub base: {FOURK_MAIN}")

# =====================================================================
# Utils
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
    quality_tags = [
        "WEBRip", "WEB-DL", "WEB", "BluRay", "HDRip", "DVDRip",
        "HDTV", "CAM", "TS", "R5", "DVDScr", "BRRip", "BDRip",
        "DVD", "PDTV", "HD"
    ]
    audio_tags = ["AAC", "AC3", "DTS", "MP3", "FLAC", "DD5", "EAC3", "Atmos"]
    sub_tags = ["ESub", "ESubs", "Subs", "MultiSub", "NoSub", "EnglishSub", "HindiSub"]
    codec_tags = ["x264", "x265", "H264", "HEVC", "AVC"]

    start = next((i for i, p in enumerate(parts) if any(tag.lower() in p.lower() for tag in quality_tags)), -1)
    end = next((i for i, p in enumerate(parts) if any(tag.lower() in p.lower() for tag in (sub_tags + audio_tags + codec_tags))), -1)
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
        except Exception:
            pass
    return 2160


def normalize_title_str(s: Optional[str]) -> str:
    if not s:
        return ""

    s = unicodedata.normalize("NFKD", s)
    s = "".join(ch for ch in s if not unicodedata.combining(ch))
    s = s.replace("&", " and ")
    s = re.sub(r"[\"'`´“”‘’]", "", s)
    s = re.sub(r"\s+", " ", s)

    return s.strip().lower()


def split_query_title_year(query: str) -> Tuple[str, Optional[int]]:
    q = query.strip()
    m = re.search(r"(19\d{2}|20\d{2})\s*\)?\s*$", q)
    if m:
        year = int(m.group(1))
        title = q[:m.start()].strip()
        title = re.sub(r"[\(\-\[\]]+$", "", title).strip()
        return normalize_title_str(title), year
    return normalize_title_str(query), None


def titles_match(query_norm: str, candidate_title: str) -> bool:
    if not query_norm:
        return False

    cand = normalize_title_str(candidate_title)
    if not cand:
        return False

    if cand == query_norm:
        return True

    if cand.startswith(query_norm) or query_norm.startswith(cand):
        return True

    if query_norm in cand:
        return True

    cand_simple = re.sub(r"[^a-z0-9]+", " ", cand)
    query_simple = re.sub(r"[^a-z0-9]+", " ", query_norm)

    cand_simple = re.sub(r"\s+", " ", cand_simple).strip()
    query_simple = re.sub(r"\s+", " ", query_simple).strip()

    if not query_simple:
        return False

    return query_simple == cand_simple or query_simple in cand_simple

# =====================================================================
# Mediator (robust)
# =====================================================================

_MEDIATOR_REGEX = re.compile(
    r"s\('o','([A-Za-z0-9+/=]+)'|ck\('_wp_http_\d+','([^']+)'",
    re.I
)


def _rot13(s: str) -> str:
    out = []
    for ch in s:
        o = ord(ch)
        if 65 <= o <= 90:
            out.append(chr((o - 65 + 13) % 26 + 65))
        elif 97 <= o <= 122:
            out.append(chr((o - 97 + 13) % 26 + 97))
        else:
            out.append(ch)
    return "".join(out)


def _b64decode_str(s: str) -> str:
    try:
        padded = s + "=" * (-len(s) % 4)
        return base64.b64decode(padded).decode("utf-8", errors="ignore")
    except Exception:
        return ""


# Quick fail hosts seen to be flaky — add more as needed
_MEDIATOR_QUICK_FAIL_HOSTS = {
    "gadgetsweb.xyz", "shorted.link", "tinyurlpro.xyz"
}


def mediator_get_redirect_links(url: str) -> str:
    """
    Defensive mediator resolver:
    - Skip known-flaky hosts quickly.
    - Try a couple lightweight attempts with slightly larger timeout.
    - Decode multiple common pipelines: base64 x2, rot13, JSON with 'o' or 'data' fields.
    - On any problem return empty string (caller will fall back).
    """
    try:
        parsed = urlparse(url)
        host = (parsed.netloc or "").lower()
        if not host or host in _MEDIATOR_QUICK_FAIL_HOSTS or is_blocked_host(url):
            logger.info(f"[mediator] skipping mediator for host: {host}")
            return ""

        last_text = ""
        attempts = 2
        for attempt in range(attempts):
            try:
                resp = http_get(url, timeout=max(_DEFAULT_TIMEOUT, 5), max_retries=0)
                last_text = resp.text or ""
                break
            except Exception as e:
                logger.warning(f"[mediator] GET attempt {attempt+1}/{attempts} failed for {url}: {e}")
                if attempt + 1 < attempts:
                    time.sleep(0.4 * (attempt + 1))
        else:
            logger.warning("[mediator] all GET attempts failed, returning empty")
            return ""

        # collect tokens from the mediator regex or long base64-like blocks
        combined = []
        for m in _MEDIATOR_REGEX.finditer(last_text):
            part = m.group(1) or m.group(2) or ""
            if part:
                combined.append(part)
        combined_str = "".join(combined).strip()

        if not combined_str:
            b64_cand = re.findall(r"([A-Za-z0-9+/]{40,}={0,2})", last_text)
            if b64_cand:
                combined_str = "".join(b64_cand[:2])

        if not combined_str:
            logger.info("[mediator] no token-like content found")
            return ""

        def try_b64(s: str) -> str:
            try:
                padded = s + "=" * (-len(s) % 4)
                return base64.b64decode(padded).decode("utf-8", errors="ignore")
            except Exception:
                return ""

        try:
            step1 = try_b64(combined_str)
            step2 = try_b64(step1) if step1 else ""
            step3 = _rot13(step2) if step2 else ""
            decoded = try_b64(step3) or try_b64(step1) or ""
            if not decoded:
                decoded = try_b64(_rot13(combined_str))
        except Exception as e:
            logger.warning(f"[mediator] decode pipeline exception: {e}")
            return ""

        if not decoded:
            logger.info("[mediator] decoding produced no text")
            return ""

        obj = None
        try:
            obj = json.loads(decoded)
        except Exception:
            # try to extract JSON substring
            mjson = re.search(r"(\{.+\})", decoded, re.S)
            if mjson:
                try:
                    obj = json.loads(mjson.group(1))
                except Exception:
                    obj = None

        if not isinstance(obj, dict):
            logger.info("[mediator] decoded content not JSON object")
            return ""

        final_url = ""
        try:
            encoded_o = obj.get("o", "") or ""
            if encoded_o:
                final_url = try_b64(encoded_o).strip()
        except Exception:
            final_url = ""

        data_raw = obj.get("data", "") or ""
        data_decoded = ""
        if data_raw:
            try:
                data_decoded = base64.b64decode(data_raw + "=" * (-len(data_raw) % 4)).decode("utf-8", errors="ignore").strip()
            except Exception:
                data_decoded = ""

        blog_url = obj.get("blog_url", "") or ""
        if not final_url and blog_url and data_decoded:
            try:
                q = urlencode({"re": data_decoded})
                blog_endpoint = blog_url + ("&" if "?" in blog_url else "?") + q
                r = http_get(blog_endpoint, timeout=max(_DEFAULT_TIMEOUT, 5), max_retries=0)
                final_url = r.text.strip()
            except Exception as e:
                logger.warning(f"[mediator] blog_url fetch failed: {e}")

        final = (final_url or "").strip()
        logger.info(f"[mediator] Resolved → {final[:120]}{'...' if len(final)>120 else ''}")
        return final
    except Exception as e:
        logger.warning(f"[mediator] unexpected failure: {e}")
        return ""


def get_redirect_links(url: str) -> str:
    """
    Return resolved redirect URL string.
    - Only call mediator for links containing 'id=' AND not blocked/quick-fail host.
    - Otherwise return url as-is.
    """
    try:
        if "id=" in url.lower():
            parsed = urlparse(url)
            host = (parsed.netloc or "").lower()
            if not host or host in _MEDIATOR_QUICK_FAIL_HOSTS or is_blocked_host(url):
                logger.info(f"[redirect] skipping mediator for {host}")
                return url
            resolved = mediator_get_redirect_links(url)
            return resolved or url
        return url
    except Exception as e:
        logger.warning(f"[redirect] failed for {url}: {e}")
        return url

# =====================================================================
# 4KHDHub
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
    q = quote_plus(query.strip())
    url = f"{FOURK_MAIN}/?s={q}"
    try:
        resp = http_get(url, timeout=SEARCH_TIMEOUT, max_retries=0)
        logger.info(f"[search_4k] url={url} status={resp.status_code} len={len(resp.text)}")
        soup = BeautifulSoup(resp.text, "html.parser")
        results = []

        for a in soup.select("div.card-grid a"):
            r = to_search_result(a, FOURK_MAIN)
            if r:
                results.append(r)

        if not results:
            for a in soup.find_all("a", href=True):
                img = a.find("img")
                if not img:
                    continue
                title = img.get("alt") or img.get("title") or a.get_text(strip=True)
                if not title:
                    continue
                href = a["href"]
                if not href:
                    continue
                if not href.startswith("http"):
                    href = urljoin(FOURK_MAIN, href)
                results.append({"title": title, "url": href, "poster": img.get("src")})

        return results
    except Exception as e:
        logger.error(f"[search_4k] failed: {e}")
        return []


def load_4k(url: str) -> Dict:
    try:
        soup = BeautifulSoup(http_get(url, timeout=_DEFAULT_TIMEOUT).text, "html.parser")
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
                filename_candidates = [
                    s for s in strings
                    if re.search(r"\.(mkv|mp4)$", s, re.I) and len(s) > 20
                ]
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
            "episodes": {
                int(s): {int(e): v for e, v in eps.items()}
                for s, eps in episode_variants.items()
            },
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
# Link helpers
# =====================================================================


def get_redirect_links(url: str) -> str:
    try:
        if "id=" in url.lower():
            return mediator_get_redirect_links(url)
        return url
    except Exception as e:
        logger.warning(f"[redirect] failed for {url}: {e}")
        return ""


def collect_links_from_variant(links_list: List[str], source_quality: int = 0) -> List[Dict]:
    """
    FAST version:

    - Do NOT resolve redirects/mediator here.
    - Just extract clean-looking URLs and carry quality.
    - Actual heavy resolution is done in /api/extract.
    """
    results = []
    for link_str in links_list:
        urls = re.findall(r'https?://[^\s\'",()\[\]]+', link_str) or [link_str]
        for u in urls:
            u = u.strip()
            if not is_valid_url(u):
                continue
            results.append({
                "name": "Unknown",
                "url": u,
                "quality": source_quality
            })
    return results


def _extract_link_param(u: str) -> Optional[str]:
    try:
        parsed = urlparse(u)
        qs = parse_qs(parsed.query)
        if "link" in qs and qs["link"]:
            return unquote(qs["link"][0])
        m = re.search(r"[?&]link=([^&]+)", u)
        if m:
            return unquote(m.group(1))
    except Exception:
        pass
    return None


def get_base_url(url: str) -> str:
    try:
        u = urlparse(url)
        return f"{u.scheme}://{u.netloc}"
    except Exception:
        return ""

# =====================================================================
# HubDrive / HubCloud (improved parity with Kotlin)
# =====================================================================


def hubdrive_extract(url: str) -> List[Dict]:
    try:
        doc = BeautifulSoup(http_get(url, timeout=HUB_TIMEOUT).text, "html.parser")
    except Exception as e:
        raise RuntimeError(f"[hubdrive] GET failed: {e}")

    href_el = doc.select_one(".btn.btn-primary.btn-user.btn-success1.m-1,a.btn.btn-primary.btn-user")
    href = href_el.get("href") if href_el and href_el.has_attr("href") else ""
    if not href:
        # fallback to first obvious download anchor
        first_a = doc.find("a", href=True)
        href = first_a.get("href") if first_a else ""
    if not href:
        raise RuntimeError(f"[hubdrive] No primary href found on {url}")

    if "hubcloud" in href.lower():
        return hubcloud_extract(href)

    return [{
        "server": "Direct",
        "quality": None,
        "url": href,
        "label": ""
    }]


def _hubcloud_get_download_href(real_url: str) -> str:
    if "hubcloud.php" in real_url:
        return real_url

    base = get_base_url(real_url)
    doc = BeautifulSoup(http_get(real_url, timeout=HUB_TIMEOUT).text, "html.parser")
    raw = doc.select_one("#download")
    href = raw.get("href") if raw and raw.has_attr("href") else ""

    if href and not href.lower().startswith("http"):
        href = base.rstrip("/") + "/" + href.lstrip("/")

    if not href:
        raise RuntimeError(f"[hubcloud] No #download href found on first page {real_url}")

    return href


def extract_gb_value(label: str) -> Optional[str]:
    if not label:
        return None
    m = re.search(r"(\d+(?:\.\d+)?)\s*GB", label, re.I)
    if not m:
        return None
    return f"{m.group(1)} GB"


def hubcloud_extract(url: str) -> List[Dict]:
    """
    Mirror Kotlin HubCloud behavior as closely as possible:
    handle FSL Server, Download File, BuzzServer, Pixeldrain, S3 Server, FSLv2, Mega Server, 10Gbps.
    Also attempt to parse embedded base64 'reurl'/'r=' tokens in scripts (hubcdn-like).
    """
    results: List[Dict] = []
    real_url = url.strip()
    if not is_valid_url(real_url):
        raise ValueError(f"[hubcloud] Invalid URL: {real_url}")

    href = _hubcloud_get_download_href(real_url)

    doc = BeautifulSoup(http_get(href, timeout=HUB_TIMEOUT).text, "html.parser")

    # try extracting encoded reurl tokens in scripts (hubcdn-like pattern)
    script_text = "".join([s.get_text() for s in doc.select("script") if s.get_text()])
    enc = None
    m_reurl = re.search(r"(?:reurl|r)=([A-Za-z0-9+/=]{20,})", script_text)
    if m_reurl:
        enc = m_reurl.group(1)
    if enc:
        try:
            dec = base64.b64decode(enc + "=" * (-len(enc) % 4)).decode("utf-8", errors="ignore")
            mlink = re.search(r'(https?://[^\s"\']+\.(?:mp4|m3u8|[^\s"\']+))', dec)
            if mlink:
                results.append({
                    "server": "HubCloud-Script",
                    "quality": None,
                    "url": mlink.group(1),
                    "label": None
                })
                return results
        except Exception:
            pass

    size_el = doc.select_one("i#size")
    size = size_el.get_text(strip=True) if size_el else ""
    header_el = doc.select_one("div.card-header")
    header = header_el.get_text(strip=True) if header_el else ""

    header_details = clean_title(header)
    label_extras = ""
    if header_details:
        label_extras += f"[{header_details}]"
    if size:
        label_extras += f"[{size}]"

    quality = get_index_quality_int(header)

    buttons = doc.select("div.card-body h2 a.btn")
    logger.info(f"[hubcloud] Found {len(buttons)} buttons")

    for btn in buttons:
        text = btn.get_text(strip=True)
        link = btn.get("href") or ""
        if not link:
            continue

        low = text.lower()
        label = extract_gb_value(label_extras)

        if "fsl server" in low:
            results.append({
                "server": "FSL Server",
                "quality": quality,
                "url": link,
                "label": label
            })
        elif "download file" in low:
            results.append({
                "server": "Direct",
                "quality": quality,
                "url": link,
                "label": label
            })
        elif "buzzserver" in low:
            try:
                r = http_get(urljoin(link, "download"), referer=link, allow_redirects=False, timeout=HUB_TIMEOUT)
                dlink = r.headers.get("hx-redirect") or r.headers.get("HX-Redirect") or ""
                if not dlink:
                    logger.warning("[hubcloud] BuzzServer: No hx-redirect header")
                else:
                    if not dlink.lower().startswith("http"):
                        dlink = get_base_url(href).rstrip("/") + "/" + dlink.lstrip("/")
                    results.append({
                        "server": "BuzzServer",
                        "quality": quality,
                        "url": dlink,
                        "label": label
                    })
            except Exception as e:
                logger.warning(f"[hubcloud] BuzzServer failed: {e}")
        elif "pixel" in low or "pixeldrain" in link:
            # normalize pixeldrain links
            if "pixeldrain.dev" in link:
                m = re.search(r"/u/([A-Za-z0-9]+)", link)
                if m:
                    file_id = m.group(1)
                    final = f"https://pixeldrain.dev/api/file/{file_id}?download"
                else:
                    final = link
            else:
                final = link
            results.append({
                "server": "Pixeldrain",
                "quality": quality,
                "url": final,
                "label": label
            })
        elif "s3 server" in low:
            results.append({
                "server": "S3 Server",
                "quality": quality,
                "url": link,
                "label": label
            })
        elif "fslv2" in low:
            results.append({
                "server": "FSLv2",
                "quality": quality,
                "url": link,
                "label": label
            })
        elif "mega server" in low:
            results.append({
                "server": "Mega Server",
                "quality": quality,
                "url": link,
                "label": label
            })
        elif "10gbps" in low:
            results.append({
                "server": "10Gbps Server (unresolved)",
                "quality": quality,
                "url": link,
                "label": label
            })
        else:
            # fallback: include raw link and let caller resolve
            results.append({
                "server": "Other",
                "quality": quality,
                "url": link,
                "label": label
            })

    if not results:
        raise RuntimeError(f"[hubcloud] No usable download buttons on {href}")

    return results

# =====================================================================
# Generic soup
# =====================================================================


def fetch_soup(url: str, timeout: int = _DEFAULT_TIMEOUT) -> Optional[BeautifulSoup]:
    try:
        r = http_get(url, timeout=timeout, max_retries=0)
        return BeautifulSoup(r.text, "html.parser")
    except Exception as e:
        logger.warning(f"[fetch_soup] Error fetching {url}: {e}")
        return None

# =====================================================================
# MoviesDrive helpers (improved md_fast_resolve)
# =====================================================================


def md_search_movies(query: str, max_pages: int = 3) -> List[Dict]:
    results = []
    q = requests.utils.requote_uri(query)

    for page in range(1, max_pages + 1):
        url = f"{MOVIESDRIVE_BASE}/page/{page}/?s={q}"
        soup = fetch_soup(url, timeout=SEARCH_TIMEOUT)
        if not soup:
            if page == 1:
                logger.warning(f"[md_search_movies] first page fetch failed for {query}")
            break

        items = soup.select("ul.recent-movies > li")
        if not items:
            break

        for li in items:
            try:
                img = li.select_one("figure img")
                a = li.select_one("figure a")
                title = img.get("title", "").replace("Download ", "").strip() if img else ""
                poster = img.get("src") if img else None
                href = a.get("href") if a else None
                if href:
                    results.append({
                        "title": title,
                        "url": href,
                        "poster": poster
                    })
            except Exception:
                continue

    return results


def md_extract_quality(s: str) -> Optional[int]:
    m = re.search(r'(\d{3,4})p', s, re.I)
    return int(m.group(1)) if m else None


def md_extract_size_label_from_text(s: str) -> Optional[str]:
    if not s:
        return None
    m = re.search(r"\[?(\d+(?:\.\d+)?)\s*(MB|GB)\]?", s, re.I)
    if not m:
        return None
    value = m.group(1)
    unit = m.group(2).upper()
    return f"{value} {unit}"


def md_extract_size_label_from_url(u: str) -> Optional[str]:
    try:
        parsed = urlparse(u)
        qs = parse_qs(parsed.query)
        if "sz" in qs and qs["sz"]:
            return qs["sz"][0]
    except Exception:
        pass
    return None


def md_extract_video_pages(item_url: str) -> List[str]:
    soup = fetch_soup(item_url, timeout=SEARCH_TIMEOUT)
    if not soup:
        return []

    pages: List[str] = []

    for a in soup.select("h5 a"):
        href = a.get("href")
        if not href:
            continue

        text = a.get_text(" ", strip=True)
        q = md_extract_quality(text)
        size_label = md_extract_size_label_from_text(text)

        if href.startswith("//"):
            full = "https:" + href
        elif not href.startswith("http"):
            full = urljoin(item_url, href)
        else:
            full = href

        if q is not None or size_label:
            parsed = urlparse(full)
            qs = parse_qs(parsed.query)
            if q is not None:
                qs["q"] = [f"{q}p"]
            if size_label:
                qs["sz"] = [size_label]
            full = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))

        if full not in pages:
            pages.append(full)

    if not pages:
        for a in soup.find_all("a", string=re.compile(r"\d{3,4}p", re.I)):
            href = a.get("href")
            if not href:
                continue

            text = a.get_text(" ", strip=True)
            q = md_extract_quality(text)
            size_label = md_extract_size_label_from_text(text)

            if href.startswith("//"):
                full = "https:" + href
            elif not href.startswith("http"):
                full = urljoin(item_url, href)
            else:
                full = href

            if q is not None or size_label:
                parsed = urlparse(full)
                qs = parse_qs(parsed.query)
                if q is not None:
                    qs["q"] = [f"{q}p"]
                if size_label:
                    qs["sz"] = [size_label]
                full = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))

            if full not in pages:
                pages.append(full)

    return pages


def md_extract_sub_links(page_url: str) -> List[str]:
    soup = fetch_soup(page_url, timeout=SEARCH_TIMEOUT)
    if not soup:
        return []

    links = set()

    for a in soup.find_all("a", href=True):
        href = a["href"]
        if is_blocked_host(href):
            continue
        if re.search(r"(pixeldrain|hubcloud|drive|embed|cloud|gdflix)", href, re.I):
            links.add(href)

    for iframe in soup.find_all("iframe", src=True):
        src = iframe["src"]
        if is_blocked_host(src):
            continue
        links.add(src)

    return list(links)


def md_fast_resolve(url: str) -> Optional[str]:
    """
    Aggressive resolver:
    - Skip blocked hosts
    - Normalize scheme
    - Look for mp4/m3u8 in HTML, <source>, <video>, og:video, iframe content, JS atob/base64 'r=' patterns
    """
    if is_blocked_host(url):
        logger.info(f"[md_fast_resolve] Skipping blocked host: {url}")
        return None

    try:
        if url.startswith("//"):
            url = "https:" + url
        if not url.startswith("http"):
            url = "https://" + url.lstrip("/")

        r = http_get(url, timeout=MD_FAST_TIMEOUT, max_retries=0)
        html = r.text or ""

        # 1) direct mp4/m3u8 in HTML
        m = re.search(r'(https?://[^\s"\']+\.(?:mp4|m3u8)(?:\?[^\s"\']*)?)', html, re.I)
        if m:
            return m.group(1)

        # parse via soup for structured elements
        soup = BeautifulSoup(html, "html.parser")

        # 2) <source src> or <video src>
        source_tag = soup.find("source", src=True)
        if source_tag and source_tag.get("src"):
            return urljoin(url, source_tag.get("src"))
        video_tag = soup.find("video", src=True)
        if video_tag and video_tag.get("src"):
            return urljoin(url, video_tag.get("src"))

        # 3) meta og:video or twitter player
        og_vid = soup.select_one("meta[property='og:video']") or soup.select_one("meta[name='twitter:player']")
        if og_vid and og_vid.has_attr("content"):
            return urljoin(url, og_vid["content"])

        # 4) iframe src — try the iframe directly
        iframe = soup.find("iframe", src=True)
        if iframe:
            iframe_src = iframe.get("src") or ""
            if re.search(r'\.(m3u8|mp4)', iframe_src, re.I):
                return urljoin(url, iframe_src)
            try:
                r2 = http_get(urljoin(url, iframe_src), timeout=min(6, MD_FAST_TIMEOUT), max_retries=0)
                m2 = re.search(r'(https?://[^\s"\']+\.(?:mp4|m3u8)[^\s"\']*)', r2.text or "", re.I)
                if m2:
                    return m2.group(1)
            except Exception:
                pass

        # 5) JS base64 or atob patterns or r= / reurl parameters (common in Hubcdn)
        js_b64 = re.search(r"(?:r=|reurl=|re=)([A-Za-z0-9+/=]{40,})", html)
        if js_b64:
            try:
                decoded = base64.b64decode(js_b64.group(1) + "=" * (-len(js_b64.group(1)) % 4)).decode("utf-8", errors="ignore")
                mm = re.search(r'(https?://[^\s"\']+\.(?:mp4|m3u8)[^\s"\']*)', decoded, re.I)
                if mm:
                    return mm.group(1)
            except Exception:
                pass

        # atob(...) patterns
        atob_match = re.search(r"atob\(['\"]([A-Za-z0-9+/=]{40,})['\"]\)", html)
        if atob_match:
            try:
                decoded = base64.b64decode(atob_match.group(1) + "=" * (-len(atob_match.group(1)) % 4)).decode("utf-8", errors="ignore")
                mm = re.search(r'(https?://[^\s"\']+\.(?:mp4|m3u8)[^\s"\']*)', decoded, re.I)
                if mm:
                    return mm.group(1)
            except Exception:
                pass

        # fallback: any quoted mp4/m3u8 in JS
        mjs = re.search(r'["\'](https?://[^"\']+\.(?:m3u8|mp4)[^"\']*)["\']', html, re.I)
        if mjs:
            return mjs.group(1)

    except Exception as e:
        logger.warning(f"[md_fast_resolve] error for {url}: {e}")

    return None


def md_detect_server(url: str) -> str:
    low = url.lower()
    if "pixeldrain" in low:
        return "Pixeldrain"
    if "r2.dev" in low:
        return "FSL Server"
    if "hubcdn" in low or "10gbps" in low:
        return "10Gbps Server (unresolved)"
    return "Other"


def md_resolve_all(pages: List[str]) -> List[Dict]:
    collected: List[Dict] = []
    source_map: Dict[str, str] = {}

    for p in pages:
        subs = md_extract_sub_links(p)
        if subs:
            for s in subs:
                if s not in source_map:
                    source_map[s] = p
        else:
            if p not in source_map:
                source_map[p] = p

    expanded = list(source_map.keys())
    logger.info(f"[md_resolve_all] pages={len(pages)} expanded={len(expanded)}")

    seen_keys = set()

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as exe:
        futures = {exe.submit(md_fast_resolve, u): u for u in expanded}
        for f in concurrent.futures.as_completed(futures):
            orig_url = futures[f]
            low = orig_url.lower()

            if "hubcloud" in low:
                try:
                    hc_links = hubcloud_extract(orig_url)
                    for e in hc_links:
                        key = (e.get("url"), e.get("server"), e.get("quality"), e.get("label"))
                        if key in seen_keys:
                            continue
                        seen_keys.add(key)

                        collected.append({
                            "url": e.get("url"),
                            "server": e.get("server") or "HubCloud",
                            "quality_hint": e.get("quality"),
                            "label": e.get("label"),
                        })
                except Exception as e:
                    logger.warning(f"[md_resolve_all] hubcloud_extract failed for {orig_url}: {e}")
                continue

            if "hubdrive" in low:
                try:
                    hd_links = hubdrive_extract(orig_url)
                    for e in hd_links:
                        key = (e.get("url"), e.get("server"), e.get("quality"), e.get("label"))
                        if key in seen_keys:
                            continue
                        seen_keys.add(key)

                        collected.append({
                            "url": e.get("url"),
                            "server": e.get("server") or "HubDrive",
                            "quality_hint": e.get("quality"),
                            "label": e.get("label"),
                        })
                except Exception as e:
                    logger.warning(f"[md_resolve_all] hubdrive_extract failed for {orig_url}: {e}")
                continue

            try:
                final_url = f.result()
            except Exception as e:
                logger.warning(f"[md_resolve_all] md_fast_resolve error for {orig_url}: {e}")
                continue

            if not final_url:
                continue

            source_page = source_map.get(orig_url, orig_url)

            q = (
                md_extract_quality(source_page) or
                md_extract_quality(orig_url) or
                md_extract_quality(final_url)
            )

            size_label = (
                md_extract_size_label_from_url(source_page) or
                md_extract_size_label_from_url(orig_url)
            )

            # Pixeldrain special-case: convert /u/{id} into /api/file/{id}?download
            if "pixeldrain.dev/u/" in final_url and "/api/file/" not in final_url:
                m = re.search(r"/u/([A-Za-z0-9]+)", final_url)
                if m:
                    file_id = m.group(1)
                    final_url = f"https://pixeldrain.dev/api/file/{file_id}?download"

            key = (final_url, None, q, size_label)
            if key in seen_keys:
                continue
            seen_keys.add(key)

            collected.append({
                "url": final_url,
                "server": None,
                "quality_hint": q,
                "label": size_label,
            })

    logger.info(f"[md_resolve_all] collected after resolve={len(collected)}")

    if not collected:
        logger.warning("[md_resolve_all] No final URLs resolved, falling back to source pages")
        for p in pages:
            q = md_extract_quality(p)
            size_label = md_extract_size_label_from_url(p)
            key = (p, None, q, size_label)
            if key in seen_keys:
                continue
            seen_keys.add(key)
            collected.append({
                "url": p,
                "server": None,
                "quality_hint": q,
                "label": size_label,
            })
        logger.info(f"[md_resolve_all] collected after fallback={len(collected)}")

    return collected


def md_basic_metadata(url: str) -> Tuple[Optional[str], Optional[str]]:
    soup = fetch_soup(url, timeout=SEARCH_TIMEOUT)
    if not soup:
        return None, None

    title = None
    poster = None

    og_title = soup.select_one("meta[property='og:title']")
    if og_title and og_title.has_attr("content"):
        title = og_title["content"].replace("Download ", "").strip()

    if not title:
        h1 = soup.select_one("h1")
        if h1:
            title = h1.get_text(strip=True)
        else:
            ttag = soup.select_one("title")
            if ttag:
                title = ttag.get_text(strip=True)

    img = soup.select_one("img[decoding='async']") or soup.select_one("figure img")
    if img and img.has_attr("src"):
        poster = img["src"]

    return title, poster

# =====================================================================
# Size helpers
# =====================================================================


def format_bytes(num: int) -> str:
    if num is None:
        return ""
    step = 1024.0
    units = ["B", "KB", "MB", "GB", "TB"]
    size = float(num)
    for unit in units:
        if size < step or unit == units[-1]:
            return f"{size:.2f} {unit}"
        size /= step


def get_remote_file_size(url: str, timeout: int = 5) -> Optional[int]:
    if is_blocked_host(url):
        logger.info(f"[size] Skipping size check for blocked host: {url}")
        return None
    try:
        resp = http_head(url, allow_redirects=True, timeout=min(timeout, 5))
        size_str = resp.headers.get("Content-Length") or resp.headers.get("content-length")
        if not size_str:
            return None
        size_str = size_str.strip()
        if not size_str.isdigit():
            return None
        return int(size_str)
    except Exception as e:
        logger.warning(f"[size] Failed to get size for {url}: {e}")
        return None

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
    size_bytes: Optional[int] = None
    size_human: Optional[str] = None


class ExtractedResponse(BaseModel):
    status: str
    total_links: int
    results: List[ExtractedLink]

# =====================================================================
# FastAPI app
# =====================================================================


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("=== Starting Lumino API (Unified 4KHDHub + MoviesDrive) ===")

    def warmup_connections():
        try:
            logger.info("Warming up HTTP connections...")
            resp = _SESSION.head(FOURK_MAIN, timeout=3)
            logger.info(f"4KHDHub connection test: {resp.status_code}")
        except Exception as e:
            logger.warning(f"Connection warmup failed (non-critical): {e}")

        try:
            if not DOMAINS_CACHE_FILE.exists():
                logger.info("Pre-fetching domains...")
                get_domains()
        except Exception as e:
            logger.warning(f"Domain pre-fetch failed (non-critical): {e}")

    warmup_thread = threading.Thread(target=warmup_connections, daemon=True)
    warmup_thread.start()

    logger.info(f"API ready - 4KHDHub: {FOURK_MAIN}")
    logger.info(f"MoviesDrive base: {MOVIESDRIVE_BASE}")
    logger.info(f"Cache directory: {CACHE_DIR}")

    yield

    logger.info("=== Shutting down Lumino API ===")
    _SESSION.close()


app = FastAPI(
    title="Lumino Unified API (4KHDHub + MoviesDrive, No-Selenium, Speed-Optimized)",
    description="4KHDHub + HubDrive/HubCloud + MoviesDrive (same endpoints, tuned for low latency)",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(requests.exceptions.RequestException)
async def request_exception_handler(request, exc):
    logger.error(f"Request error: {exc}")
    return JSONResponse(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        content={
            "detail": "Upstream service temporarily unavailable. Please retry.",
            "error_type": type(exc).__name__
        }
    )


# =====================================================================
# ChromeOs (cache, cinemaos, helper functions)
# =====================================================================

_CLEAN_RE = re.compile(r"\s{2,}")

# In-memory cache (simple, per-process)
CACHE_TTL_SECONDS = 300  # 5 minutes
CACHE_MAX_ENTRIES = 1000
cinemaos_cache: Dict[str, Tuple[float, Dict[str, Any]]] = {}

# Global HTTP client (lazy init, reused)
HTTP_CLIENT: Optional[httpx.AsyncClient] = None


def get_http_client() -> httpx.AsyncClient:
    global HTTP_CLIENT
    if HTTP_CLIENT is None:
        HTTP_CLIENT = httpx.AsyncClient(timeout=60.0)
    return HTTP_CLIENT


def _generate_hashed_string_once() -> str:
    """
    One-time cost to compute the master key string used by cinemaos_generate_hash.
    HMAC-SHA512(key = GEN_HASH_S, input = "crypto_rotation_v2_seed_2025"),
    hex, repeat * 3, slice to max(len(s), 128).
    """
    s = GEN_HASH_S
    a = "2"
    algorithm_key = s.encode("utf-8")
    input_str = f"crypto_rotation_v{a}_seed_2025".encode("utf-8")
    mac = hmac.new(algorithm_key, input_str, hashlib.sha512).digest()
    hexed = mac.hex()
    repeated = (hexed * 3)[: max(len(s), 128)]
    return repeated


CINEMAOS_MASTER_KEY = _generate_hashed_string_once()



_CINEMAOS_PRIMARY_KEY = "a7f3b9c2e8d4f1a6b5c9e2d7f4a8b3c6e1d9f7a4b2c8e5d3f9a6b4c1e7d2f8a5"
_CINEMAOS_SECONDARY_KEY = "d3f8a5b2c9e6d1f7a4b8c5e2d9f3a6b1c7e4d8f2a9b5c3e7d4f1a8b6c2e9d5f3"


def _create_cinemaos_content_string(
    tmdb_id: str,
    imdb_id: str,
    season_id: str,
    episode_id: str,
) -> str:
    """
    Port of Kotlin createContentString:
    Join only the present fields as: tmdbId:xxx|imdbId:yyy|seasonId:...|episodeId:...
    (order preserved as in Kotlin)
    """
    parts = []
    if tmdb_id:
        parts.append(f"tmdbId:{tmdb_id}")
    if imdb_id:
        parts.append(f"imdbId:{imdb_id}")
    if season_id:
        parts.append(f"seasonId:{season_id}")
    if episode_id:
        parts.append(f"episodeId:{episode_id}")
    return "|".join(parts)


def _hmac_sha256_hex(key_bytes: bytes, msg: str) -> str:
    return hmac.new(key_bytes, msg.encode("utf-8"), hashlib.sha256).hexdigest()


def cinemaos_generate_hash(
    tmdb_id: str,
    season_id: str,
    episode_id: str,
    is_series: bool,
) -> str:
    """
    Faithful port of Kotlin cinemaOSGenerateHash:
      content = createContentString(...)
      first = HMAC-SHA256(content, primary)
      final = HMAC-SHA256(first, secondary)
      return final (hex)
    """
    # Build content using tmdb/imdb/season/episode (Kotlin uses only present parts)
    # Note: callers may pass empty strings for season/episode when not present
    content = _create_cinemaos_content_string(tmdb_id, "", season_id, episode_id) \
        if (tmdb_id and (season_id or episode_id)) else _create_cinemaos_content_string(tmdb_id, "", season_id, episode_id)

    # Primary/secondary keys are hex-like constant strings from Kotlin implementation
    primary_bytes = _CINEMAOS_PRIMARY_KEY.encode("utf-8")
    secondary_bytes = _CINEMAOS_SECONDARY_KEY.encode("utf-8")

    first = _hmac_sha256_hex(primary_bytes, content)
    final = _hmac_sha256_hex(secondary_bytes, first)
    return final


def pbkdf2_derive_key(
    password_bytes: bytes, salt_bytes: bytes, iterations: int = 100000, length: int = 32
) -> bytes:
    """
    PBKDF2WithHmacSHA256, 100000 iterations, 32 bytes (AES-256).
    Must match Kotlin exactly.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt_bytes,
        iterations=iterations,
    )
    return kdf.derive(password_bytes)


def hex_to_bytes(h: str) -> bytes:
    """
    Hex string -> bytes. Strict and fast.
    """
    h = h.strip()
    if len(h) % 2 != 0:
        h = "0" + h
    try:
        return binascii.unhexlify(h)
    except binascii.Error as e:
        raise ValueError(f"invalid hex: {h!r} ({e})")


def cinemaos_decrypt_response(data_obj: Any) -> str:
    """
    Port of Kotlin cinemaOSDecryptResponse behaviour:
    - Accept either dict or JSON string for data_obj
    - Expect fields: encrypted, cin, mao, salt (hex strings)
    - PBKDF2WithHmacSHA256(password = password_literal_as_chars, salt, iterations=100000, length=32)
    - AES-256-GCM decrypt with IV=cin (bytes), ciphertext=encrypted (bytes), auth_tag=mao (bytes) appended to ciphertext
    Returns plaintext string (JSON) on success, raises descriptive errors on failure.
    """
    if data_obj is None:
        raise ValueError("no data to decrypt")

    # If it's a JSON string, try to parse
    if isinstance(data_obj, str):
        try:
            data_obj = json.loads(data_obj)
        except Exception:
            # keep as-is and let next validation fail with clear message
            pass

    if not isinstance(data_obj, dict):
        raise ValueError("unexpected data format for decryption (expected dict or JSON string)")

    encrypted_hex = str(data_obj.get("encrypted", "")).strip()
    cin_hex = str(data_obj.get("cin", "")).strip()
    mao_hex = str(data_obj.get("mao", "")).strip()
    salt_hex = str(data_obj.get("salt", "")).strip()

    if not (encrypted_hex and cin_hex and mao_hex and salt_hex):
        raise ValueError("missing one or more required fields for decryption (encrypted/cin/mao/salt)")

    try:
        iv = hex_to_bytes(cin_hex)
        auth_tag = hex_to_bytes(mao_hex)
        cipher_bytes = hex_to_bytes(encrypted_hex)
        salt = hex_to_bytes(salt_hex)
    except Exception as e:
        raise ValueError(f"hex parsing failed: {e}")

    # Match Kotlin's password literal — they used a long hex-like literal and then constructed a PBEKeySpec from its bytes->chars.
    # The simplest compatible approach is to use the same string decoded to bytes and also provide the same bytes when deriving.
    password_literal = (
        "a1b2c3d4e4f6477658455678901477567890abcdef1234567890abcdef123456"
    )

    # Kotlin converted key bytes to chars in PBEKeySpec by mapping each byte to a Java char.
    # We'll mimic that by constructing a 'char string' where each character has codepoint equal to the byte value,
    # then encode to UTF-8 to obtain bytes for PBKDF2's password input. PBKDF2HMAC accepts a bytes-like password.
    try:
        key_bytes_raw = password_literal.encode("utf-8")
        # mimic Java's bytes->char[] -> effectively produce a string of chars with codepoint == raw byte value
        # Then encode that string using latin-1 to preserve single-byte values 0..255 as bytes 0..255.
        # This approximates the Java char->bytes behaviour for 0..255 values.
        password_pseudo_chars = ''.join(chr(b) for b in key_bytes_raw)
        password_for_pbkdf2 = password_pseudo_chars.encode("latin-1")
    except Exception:
        # fallback to simple utf-8 if unusual
        password_for_pbkdf2 = password_literal.encode("utf-8")

    # Derive key using PBKDF2-HMAC-SHA256, 100000 iterations, 32 bytes (256 bits)
    try:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = kdf.derive(password_for_pbkdf2)
    except Exception as e:
        raise RuntimeError(f"pbkdf2 derive failed: {e}")

    # AES-GCM decrypt: combine ciphertext + auth_tag as Kotlin does (cipher.doFinal(encrypted + tag))
    aesgcm = AESGCM(key)
    combined = cipher_bytes + auth_tag
    try:
        plaintext_bytes = aesgcm.decrypt(iv, combined, None)
    except Exception as e:
        raise RuntimeError(f"AES-GCM decryption failed: {e}")

    try:
        plaintext = plaintext_bytes.decode("utf-8")
    except Exception as e:
        raise RuntimeError(f"utf-8 decode failed on plaintext: {e}")

    return plaintext


def parse_cinemaos_sources(json_string: str) -> List[Dict[str, Any]]:
    """
    Port of parseCinemaOSSources.
    Expecting JSON with 'sources' object mapping server keys to objects.
    Flatten into list entries with keys: server,url,type,speed,bitrate,quality
    """
    out: List[Dict[str, Any]] = []
    try:
        obj = json.loads(json_string)
    except Exception as e:
        raise ValueError(f"invalid json in decrypted payload: {e}")

    if "sources" not in obj:
        return out

    sources = obj["sources"]

    if isinstance(sources, dict):
        for key, source in sources.items():
            if (
                isinstance(source, dict)
                and "qualities" in source
                and isinstance(source["qualities"], dict)
            ):
                for qkey, qobj in source["qualities"].items():
                    if isinstance(qobj, dict):
                        url = qobj.get("url", "")
                        typ = qobj.get("type", "")
                    else:
                        url = str(qobj)
                        typ = ""
                    entry = {
                        "server": source.get("server", key),
                        "url": url,
                        "type": typ,
                        "speed": source.get("speed", ""),
                        "bitrate": source.get("bitrate", ""),
                        "quality": str(qkey),
                    }
                    out.append(entry)
            else:
                if isinstance(source, dict):
                    entry = {
                        "server": source.get("server", key),
                        "url": source.get("url", ""),
                        "type": source.get("type", ""),
                        "speed": source.get("speed", ""),
                        "bitrate": source.get("bitrate", ""),
                        "quality": source.get("quality", ""),
                    }
                else:
                    entry = {
                        "server": key,
                        "url": str(source),
                        "type": "",
                        "speed": "",
                        "bitrate": "",
                        "quality": "",
                    }
                out.append(entry)

    elif isinstance(sources, list):
        for source in sources:
            if isinstance(source, dict):
                entry = {
                    "server": source.get("server", ""),
                    "url": source.get("url", ""),
                    "type": source.get("type", ""),
                    "speed": source.get("speed", ""),
                    "bitrate": source.get("bitrate", ""),
                    "quality": source.get("quality", ""),
                }
                out.append(entry)

    return out


def infer_type(type_str: str) -> str:
    """
    Map Kotlin ExtractorLinkType to simple string used by your backend.
    """
    t = (type_str or "").lower()
    if "hls" in t or "m3u8" in t:
        return "m3u8"
    if "dash" in t:
        return "dash"
    if "mp4" in t or "video" in t:
        return "mp4"
    return "auto"  # fallback


def infer_quality_from_fields(quality_str: str, bitrate_str: str) -> int:
    """
    Approximation of Kotlin quality logic:
    - if quality numeric -> that number
    - else check quality text for fhd/hd/etc.
    - else fallback to bitrate text
    - default 1080
    """
    q = (quality_str or "").strip().lower()
    b = (bitrate_str or "").strip().lower()

    # direct numeric
    if q.isdigit():
        return int(q)

    def from_text(txt: str) -> Optional[int]:
        txt = txt.lower()
        if "4k" in txt or "2160" in txt:
            return 2160
        if "1440" in txt or "2k" in txt:
            return 1440
        if "fhd" in txt or "1080" in txt:
            return 1080
        if "hd" in txt or "720" in txt:
            return 720
        if "480" in txt:
            return 480
        if "360" in txt:
            return 360
        return None

    # first try quality field
    qv = from_text(q)
    if qv is not None:
        return qv

    # then try bitrate hints
    bv = from_text(b)
    if bv is not None:
        return bv

    # default if nothing matched
    return 1080


def clean_name(s: str) -> str:
    return _CLEAN_RE.sub(" ", s).strip()


def make_cache_key(
    tmdb_id: int,
    season: Optional[int],
    episode: Optional[int],
    title: Optional[str],
    year: Optional[int],
    imdb_id: Optional[str],
) -> str:
    """
    Deterministic cache key for a specific request.
    """
    payload = {
        "tmdb_id": tmdb_id,
        "season": season,
        "episode": episode,
        "title": title or "",
        "year": year or 0,
        "imdb_id": imdb_id or "",
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def cache_get(key: str) -> Optional[Dict[str, Any]]:
    """
    Get from in-memory cache if not expired.
    """
    now = time.time()
    entry = cinemaos_cache.get(key)
    if not entry:
        return None
    ts, data = entry
    if now - ts > CACHE_TTL_SECONDS:
        cinemaos_cache.pop(key, None)
        return None
    return data


def cache_put(key: str, data: Dict[str, Any]) -> None:
    """
    Store in in-memory cache with TTL and simple max size control.
    """
    now = time.time()
    if len(cinemaos_cache) >= CACHE_MAX_ENTRIES:
        # Drop oldest-ish item (not perfect LRU, but good enough)
        oldest_key = min(cinemaos_cache.items(), key=lambda kv: kv[1][0])[0]
        cinemaos_cache.pop(oldest_key, None)
    cinemaos_cache[key] = (now, data)

# =====================================================================
# API ENDPOINT
# =====================================================================


@app.get("/")
async def root():
    return {"message": "Welcome to Lumino Unified API", "status": "running"}


@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "cache_dir": CACHE_DIR,
        "fourk_main": FOURK_MAIN,
        "moviesdrive_base": MOVIESDRIVE_BASE,
        "fast_extract_mode": FAST_EXTRACT_MODE,
        "default_timeout": _DEFAULT_TIMEOUT,
        "max_retries": _MAX_RETRIES_GLOBAL,
        "search_timeout": SEARCH_TIMEOUT,
        "hub_timeout": HUB_TIMEOUT,
        "md_fast_timeout": MD_FAST_TIMEOUT,
        "max_variants_per_entry": MAX_VARIANTS_PER_ENTRY,
        "max_extract_links": MAX_EXTRACT_LINKS,
    }

# =====================================================================
# /api/search  (PARALLEL 4K + MoviesDrive)
# =====================================================================


@app.post("/api/search")
async def api_search(request: SearchRequest):
    logger.info(f"[api_search] {request.query}")
    title_q, year_q = split_query_title_year(request.query)

    try:
        # Run 4K and MoviesDrive search in parallel
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:
            f_4k = ex.submit(search_4k, request.query)
            f_md = ex.submit(md_search_movies, request.query)
            raw_4k = f_4k.result()
            raw_md = f_md.result()

        matches_4k: List[Dict] = []
        for r in raw_4k:
            t_raw = r.get("title", "") or ""
            base_title = t_raw
            year_r: Optional[int] = None

            m = re.search(r"(.*?)\s*\((19\d{2}|20\d{2})\)", t_raw)
            if m:
                base_title = m.group(1)
                year_r = int(m.group(2))

            # For speed, skip extra load_4k(year) refinement; rely on title + optional year in title.
            if not titles_match(title_q, base_title):
                continue
            if year_q is not None and year_r is not None and year_r != year_q:
                continue

            r_out = dict(r)
            r_out["source"] = "4khdhub"
            r_out["year"] = year_r
            matches_4k.append(r_out)

        matches_md: List[Dict] = []
        for r in raw_md:
            t_raw = r.get("title", "") or ""
            base_title = t_raw
            year_r: Optional[int] = None

            m = re.search(r"(.*?)\s*(?:\(|\[)?(19\d{2}|20\d{2})(?:\)|\])?", t_raw)
            if m:
                base_title = m.group(1)
                year_r = int(m.group(2))

            if not titles_match(title_q, base_title):
                continue
            if year_q is not None and year_r is not None and year_r != year_q:
                continue

            r_out = dict(r)
            r_out["source"] = "moviesdrive"
            r_out["year"] = year_r
            matches_md.append(r_out)

        combined_map: Dict[Tuple[str, Optional[int]], Dict] = {}

        for r in matches_4k:
            base_title = r.get("title", "")
            norm = normalize_title_str(base_title)
            key_year = r.get("year")
            key = (norm, key_year)
            if key not in combined_map:
                combined_map[key] = r

        for r in matches_md:
            base_title = r.get("title", "")
            norm = normalize_title_str(base_title)
            key_year = r.get("year")
            key = (norm, key_year)
            if key not in combined_map:
                combined_map[key] = r

        final_results = list(combined_map.values())

        return {
            "status": "success",
            "count": len(final_results),
            "results": final_results
        }

    except requests.exceptions.Timeout:
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail="Search service timeout. Please retry."
        )
    except requests.exceptions.ConnectionError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Cannot connect to search services. Please retry."
        )
    except Exception as e:
        logger.error(f"Search error: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Search failed: {str(e)}"
        )

# =====================================================================
# /api/get-links
# =====================================================================


@app.post("/api/get-links")
async def api_get_links(request: LinksRequest):
    if not request.url:
        raise HTTPException(status_code=400, detail="URL is required")

    logger.info(f"[api_get_links] {request.url}")

    parsed = urlparse(request.url)
    host = (parsed.netloc or "").lower()

    fourk_host = urlparse(FOURK_MAIN).netloc.lower()

    try:
        if fourk_host in host or "4khdhub" in host:
            data = load_4k(request.url)
            if not data:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Content not found or failed to load. The URL may be invalid."
                )

            type_ = data["type"]
            title = data["title"]
            logger.info(f"[get-links] 4KHDHub loaded: {title} ({type_})")

            metadata = {
                "title": title,
                "type": type_,
                "url": data["url"],
                "poster": data.get("poster", ""),
                "year": data.get("year"),
                "plot": data.get("plot", ""),
                "tags": data.get("tags", [])
            }

            variants = []
            if type_ == "TvSeries":
                if request.season is None or request.episode is None:
                    raise HTTPException(
                        status_code=400,
                        detail="Season and episode are required for TV series"
                    )
                season = request.season
                episode = request.episode
                variants = data["episodes"].get(season, {}).get(episode, [])
                if not variants:
                    raise HTTPException(
                        status_code=404,
                        detail=f"Episode S{season:02d}E{episode:02d} not found"
                    )
                metadata["season"] = season
                metadata["episode"] = episode
                metadata["episode_name"] = f"S{season:02d}E{episode:02d}"
            else:
                if request.season is not None or request.episode is not None:
                    raise HTTPException(
                        status_code=400,
                        detail="Season and episode should not be provided for movies"
                    )
                variants = data.get("variants", [])

            if not variants:
                raise HTTPException(
                    status_code=404,
                    detail="No download variants found for this content"
                )

            # LIMIT how many we expand to keep response fast
            if len(variants) > MAX_VARIANTS_PER_ENTRY:
                variants = sorted(variants, key=lambda v: v.get("quality", 0), reverse=True)[
                    :MAX_VARIANTS_PER_ENTRY
                ]

            selected = variants
            logger.info(f"[get-links] 4KHDHub selected {len(selected)} variants")

            collected = []
            with concurrent.futures.ThreadPoolExecutor(max_workers=5) as ex:
                futures = {
                    ex.submit(collect_links_from_variant, sv["links"], sv["quality"]): sv
                    for sv in selected
                }
                for f in concurrent.futures.as_completed(futures, timeout=30):
                    try:
                        collected.extend(f.result())
                    except Exception as e:
                        logger.warning(f"[collect] error: {e}")

            # IMPORTANT: keep all unique URLs (no resolving or host filtering here)
            filtered = []
            seen = set()
            for item in collected:
                url = item.get("url", "")
                if not url or url in seen:
                    continue
                seen.add(url)
                filtered.append(url)

            logger.info(f"[get-links] 4KHDHub extracted {len(filtered)} raw links for extraction")

            return {
                "status": "success",
                "metadata": metadata,
                "hubdrive_links": filtered,
                "total_links": len(filtered),
                "source": "4khdhub"
            }

        elif "moviesdrive" in host:
            pages = md_extract_video_pages(request.url)
            if not pages:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="No video pages found for this MoviesDrive URL"
                )

            title, poster = md_basic_metadata(request.url)

            metadata = {
                "title": title or "",
                "type": "MoviesDrive",
                "url": request.url,
                "poster": poster or "",
                "year": None,
                "plot": "",
                "tags": []
            }

            logger.info(f"[get-links] MoviesDrive extracted {len(pages)} video pages")

            return {
                "status": "success",
                "metadata": metadata,
                "hubdrive_links": pages,
                "total_links": len(pages),
                "source": "moviesdrive"
            }

        else:
            raise HTTPException(
                status_code=400,
                detail=f"Unsupported host: {host}. Only 4KHDHub and MoviesDrive URLs are supported."
            )

    except HTTPException:
        raise
    except concurrent.futures.TimeoutError:
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail="Link collection timeout. Please retry."
        )
    except requests.exceptions.Timeout:
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail="Upstream service timeout. Please retry."
        )
    except requests.exceptions.ConnectionError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Cannot connect to content service. Please retry."
        )
    except Exception as e:
        logger.error(f"Get-links error: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get links: {str(e)}"
        )

# =====================================================================
# /api/extract (FULLY CONCURRENT, GRACEFUL DEGRADATION)
# =====================================================================


def _process_single_extract_link(url: str) -> Tuple[List[Dict], Optional[str], int]:
    """
    Process a single URL for /api/extract:

    - If it's hubcloud/hubdrive (or resolves to it), extract directly.
    - If hubcloud/hubdrive extraction hard-fails, return an unresolved placeholder
      instead of marking the whole link as failed.
    - Otherwise, return it as a candidate MoviesDrive/other page (md_page).
    - failed_flag = 1 only for unexpected errors outside those cases.
    """
    try:
        low = (url or "").lower()
        links: List[Dict] = []

        # Direct hubcloud/hubdrive
        if "hubcloud" in low:
            try:
                links = hubcloud_extract(url)
                return links, None, 0
            except Exception as e:
                logger.warning(f"[_process_single_extract_link] hubcloud_extract hard failure for {url}: {e}")
                return [{
                    "server": "HubCloud (unresolved)",
                    "quality": None,
                    "url": url,
                    "label": None
                }], None, 0

        if "hubdrive" in low:
            try:
                links = hubdrive_extract(url)
                return links, None, 0
            except Exception as e:
                logger.warning(f"[_process_single_extract_link] hubdrive_extract hard failure for {url}: {e}")
                return [{
                    "server": "HubDrive (unresolved)",
                    "quality": None,
                    "url": url,
                    "label": None
                }], None, 0

        # Try mediator/redirects
        resolved = get_redirect_links(url)
        low_res = (resolved or "").lower()

        if "hubcloud" in low_res:
            try:
                links = hubcloud_extract(resolved)
                return links, None, 0
            except Exception as e:
                logger.warning(f"[_process_single_extract_link] hubcloud_extract hard failure after mediator for {resolved}: {e}")
                return [{
                    "server": "HubCloud (unresolved)",
                    "quality": None,
                    "url": resolved,
                    "label": None
                }], None, 0

        if "hubdrive" in low_res:
            try:
                links = hubdrive_extract(resolved)
                return links, None, 0
            except Exception as e:
                logger.warning(f"[_process_single_extract_link] hubdrive_extract hard failure after mediator for {resolved}: {e}")
                return [{
                    "server": "HubDrive (unresolved)",
                    "quality": None,
                    "url": resolved,
                    "label": None
                }], None, 0

        # Not hubcloud/hubdrive even after resolution -> maybe MoviesDrive/other
        target = resolved or url
        return [], target, 0

    except Exception as e:
        logger.warning(f"[_process_single_extract_link] failed for {url}: {e}")
        return [], None, 1


@app.post("/api/extract", response_model=ExtractedResponse)
def extract_links(req: HubDriveRequest):
    if not req.hubdrive_links:
        raise HTTPException(
            status_code=400,
            detail="No hubdrive links provided"
        )

    # LIMIT number of links per call to keep latency low
    incoming_links = req.hubdrive_links[:MAX_EXTRACT_LINKS]

    all_links: List[Dict] = []
    failed_count = 0
    md_video_pages: List[str] = []

    # --- CONCURRENT per-URL processing ---
    max_workers = min(len(incoming_links), 10) or 1
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {
            ex.submit(_process_single_extract_link, url): url
            for url in incoming_links
        }
        for fut in concurrent.futures.as_completed(futures):
            try:
                links, md_page, failed_flag = fut.result()
            except Exception as e:
                logger.warning(f"[extract] worker failed: {e}")
                failed_count += 1
                continue

            if failed_flag:
                failed_count += 1

            if links:
                all_links.extend(links)
            if md_page:
                md_video_pages.append(md_page)

    # --- MoviesDrive / generic pages (already batched) ---
    if md_video_pages:
        try:
            md_resolved = md_resolve_all(md_video_pages)
            for item in md_resolved:
                final_url = item["url"]

                q_hint = item.get("quality_hint")
                server = item.get("server") or md_detect_server(final_url)
                quality = q_hint or md_extract_quality(final_url)
                label = item.get("label")

                all_links.append({
                    "server": server,
                    "quality": quality,
                    "url": final_url,
                    "label": label
                })
        except Exception as e:
            logger.warning(f"[extract] MoviesDrive resolve failed: {e}")
            failed_count += len(md_video_pages)

    # --- Final filtering ---
    filtered_links = [
        x for x in all_links
        if (x.get("server") or "").strip().lower() != "unknown server"
    ]

    # Instead of raising 404/503, always return success with whatever we have.
    # Client should check total_links and failed_count.
    if not filtered_links:
        logger.warning(
            f"[extract] No valid download links; failed_count={failed_count}, incoming={len(incoming_links)}"
        )
        return {
            "status": "success",
            "total_links": 0,
            "results": [],
            "failed_count": failed_count
        }

    # FAST mode: skip size probing
    if FAST_EXTRACT_MODE:
        return {
            "status": "success",
            "total_links": len(filtered_links),
            "results": filtered_links,
            "failed_count": failed_count
        }

    # --- Optional: size probing (still concurrent) ---
    def _fetch_size(idx: int, item: Dict) -> Tuple[int, Optional[int]]:
        if "size_bytes" in item and item.get("size_bytes") is not None:
            return idx, item["size_bytes"]
        url = item.get("url")
        if not url:
            return idx, None
        size = get_remote_file_size(url, timeout=5)
        return idx, size

    size_map: Dict[int, Optional[int]] = {}

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as ex:
        futures = {
            ex.submit(_fetch_size, i, item): i
            for i, item in enumerate(filtered_links)
        }
        for fut in concurrent.futures.as_completed(futures):
            try:
                idx, size = fut.result()
                size_map[idx] = size
            except Exception as e:
                logger.warning(f"[size] error in future: {e}")

    for i, item in enumerate(filtered_links):
        size = size_map.get(i)
        if size is not None:
            item["size_bytes"] = size
            item["size_human"] = format_bytes(size)

    return {
        "status": "success",
        "total_links": len(filtered_links),
        "results": filtered_links,
        "failed_count": failed_count
    }
    

@app.get("/cinemaos")
async def get_cinemaos(
    tmdb_id: int = Query(..., description="tmdb id"),
    season: Optional[int] = Query(None),
    episode: Optional[int] = Query(None),
    title: Optional[str] = Query(None),
    year: Optional[int] = Query(None),
    imdb_id: Optional[str] = Query(None),
):
    """
    /cinemaos endpoint that mirrors the Kotlin client:
    - Uses /api/provider
    - Builds content string and computes secret with cinemaos_generate_hash (Kotlin port)
    - Decrypts response using cinemaos_decrypt_response
    - Returns 'sources' list with headers and debug info
    """
    is_series = season is not None
    tmdb_str = str(tmdb_id)
    season_str = str(season) if season is not None else ""
    episode_str = str(episode) if episode is not None else ""
    fix_title = quote_plus(title) if title else ""
    imdb_val = imdb_id or ""

    cache_key = make_cache_key(tmdb_id, season, episode, title, year, imdb_id)
    cached = cache_get(cache_key)
    if cached is not None:
        cached_copy = json.loads(json.dumps(cached))
        if "debug" in cached_copy:
            cached_copy["debug"]["cached"] = True
        return cached_copy

    # generate secret using Kotlin-style function
    secret = cinemaos_generate_hash(tmdb_str, season_str, episode_str, is_series)

    typ = "tv" if is_series else "movie"
    base_path = f"{CINEMAOS_API}/api/provider"
    if is_series:
        url = (
            f"{base_path}?type={typ}"
            f"&tmdbId={tmdb_id}"
            f"&imdbId={imdb_val}"
            f"&seasonId={season}"
            f"&episodeId={episode}"
            f"&t={fix_title}"
            f"&ry={year or ''}"
            f"&secret={secret}"
        )
    else:
        url = (
            f"{base_path}?type={typ}"
            f"&tmdbId={tmdb_id}"
            f"&imdbId={imdb_val}"
            f"&t={fix_title}"
            f"&ry={year or ''}"
            f"&secret={secret}"
        )

    headers = {
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.9",
        "Connection": "keep-alive",
        "Referer": CINEMAOS_API,
        "Host": urlparse(CINEMAOS_API).netloc,
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-origin",
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/139.0.0.0 Safari/537.36"
        ),
        "sec-ch-ua": '"Not;A=Brand";v="99", "Google Chrome";v="139", "Chromium";v="139"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "Content-Type": "application/json",
    }

    client = get_http_client()
    resp = await client.get(url, headers=headers)
    if resp.status_code != 200:
        raise HTTPException(
            status_code=502,
            detail=f"cinemaos api returned {resp.status_code}: {resp.text[:400]}"
        )

    try:
        body = resp.json()
    except Exception:
        body = resp.text

    if isinstance(body, dict) and "data" in body:
        data_field = body["data"]
    else:
        raise HTTPException(
            status_code=502,
            detail=f"unexpected cinemaos response format (missing 'data'), raw: {str(body)[:400]}"
        )

    try:
        decrypted = cinemaos_decrypt_response(data_field)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"decryption failed: {e}")

    try:
        sources = parse_cinemaos_sources(decrypted)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"parsing decrypted payload failed: {e}")

    final_sources = []
    for it in sources:
        url_val = it.get("url", "") or ""
        if not url_val:
            continue

        extractor_type = infer_type(it.get("type", ""))
        bitrate = it.get("bitrate", "") or ""
        quality_field = it.get("quality", "") or ""
        server = it.get("server", "") or ""

        quality_val = infer_quality_from_fields(quality_field, bitrate)

        name_raw = f"CinemaOS [{server}] {bitrate} {it.get('speed','')}"
        name = clean_name(name_raw)

        final_sources.append(
            {
                "name": name,
                "label": name,
                "url": url_val,
                "type": extractor_type,
                "quality": quality_val,
                "headers": {"Referer": CINEMAOS_API},
            }
        )

    response_payload = {
        "sources": final_sources,
        "debug": {
            "secret_used": secret,
            "source_count": len(final_sources),
            "upstream_url": url,
            "cached": False,
        },
    }

    cache_put(cache_key, response_payload)
    return response_payload


# =====================================================================
# Entrypoint
# =====================================================================

if __name__ == "__main__":
    logger.info("Starting Lumino Unified API on port 7860 (speed-optimized)")
    uvicorn.run(app, host="0.0.0.0", port=7860, log_level="info")
