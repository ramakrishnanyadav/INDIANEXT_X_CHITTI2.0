import logging
from urllib.parse import urlparse, parse_qs, unquote
from typing import Dict, Any

import httpx  # type: ignore[import]

logger = logging.getLogger("sentineliq.unwinder")

# Known wrappers and the query parameter containing the destination
KNOWN_WRAPPERS = {
    "google.com": ["q", "url"],
    "facebook.com": ["u"],
    "youtube.com": ["q"],
    "linkedin.com": ["url"],
    "bing.com": ["url"],
    "l.instagram.com": ["u"],
}

# Known shorteners that need a HEAD request
KNOWN_SHORTENERS = {
    "bit.ly", "t.co", "tinyurl.com", "is.gd", "buff.ly", "ow.ly", "goo.gl"
}

class RedirectUnwinder:
    @classmethod
    async def unwind(cls, url: str) -> Dict[str, Any]:
        """
        Unwind redirects to find the final destination.
        Returns the final URL, the redirect depth, and intermediate wrappers.
        """
        depth = 0
        wrappers = []
        current_url = url
        
        # Guard against infinite loops
        max_depth = 5
        
        while depth < max_depth:
            parsed = urlparse(current_url)
            hostname = str(parsed.hostname or "").lower()
            if hostname.startswith("www."):
                hostname = hostname[4:]
                
            # 1. Check known wrappers (e.g. google.com/url?q=)
            extracted = False
            for wrapper_host, params in KNOWN_WRAPPERS.items():
                if hostname == wrapper_host or hostname.endswith(f".{wrapper_host}"):
                    query = parse_qs(parsed.query)
                    for param in params:
                        if param in query and query[param]:
                            next_url = unquote(query[param][0])
                            if next_url.startswith("http"):
                                wrappers.append(hostname)
                                current_url = next_url
                                depth += 1
                                extracted = True
                                break
                    if extracted:
                        break
            
            if extracted:
                continue
                
            # 2. Check known shorteners (requires network request)
            if hostname in KNOWN_SHORTENERS:
                try:
                    async with httpx.AsyncClient(timeout=3.0, follow_redirects=False) as client:
                        resp = await client.head(current_url)
                        if 300 <= resp.status_code < 400 and "location" in resp.headers:
                            wrappers.append(hostname)
                            current_url = resp.headers["location"]
                            depth += 1
                            continue
                except Exception as e:
                    logger.debug(f"Failed to unwind shortener {current_url}: {e}")
                    # Stop unwinding if network fails
                    break
                    
            # If no extraction or shortener applied, we reached the end
            break
            
        return {
            "final_url": current_url,
            "redirect_depth": depth,
            "wrappers": wrappers
        }
