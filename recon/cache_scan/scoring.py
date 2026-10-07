"""
Cache Poisoning Scanner — Confidence scoring (Phase 5 of the native engine).

Cache poisoning results are high-noise; analysts distrust raw differential output.
This module turns a confirmation record into a confidence score + tier so only
trustworthy findings reach the graph. Inspired by the HCache validation model and
CacheX persistence logic described in the design doc.

Tiers (per the design doc):
  Confirmed  0.95-0.99  benign canary persists on a CLEAN request that was an
                        explicit cache HIT, and repetition succeeds.
  Strong     0.80-0.94  poisoned behaviour persists on a clean cache HIT, or a
                        reflected canary persists behind a silent cache (no
                        cache-status header, so the hit can only be inferred).
  Tentative  0.50-0.79  a behavioural change persisted, but no header shows the
                        clean read came from the cache.
  Rejected   <0.50      change did not survive clean validation, or the clean read
                        was an explicit MISS (served by the origin, not the cache).
"""


def score_finding(confirmation: dict) -> tuple[float, str]:
    """Map a confirmation record to (confidence, tier).

    Expected confirmation keys (from confirm.py):
      reflected_in_baseline (bool)  - payload changed the immediate response
      persisted_on_clean (bool)     - canary returned on a clean (no-payload) request
      clean_cache_state (str)       - that clean response: "hit" | "miss" | "unknown"
      cache_hit_on_clean (bool)     - legacy shape of clean_cache_state == "hit"
      repeated_ok (bool)            - second clean request also returned the canary
      stable (bool)                 - responses were stable across repeats
    """
    reflected = confirmation.get("reflected_in_baseline", False)
    persisted = confirmation.get("persisted_on_clean", False)
    cache_hit = confirmation.get("cache_hit_on_clean", False)
    state = confirmation.get("clean_cache_state") or ("hit" if cache_hit else "unknown")
    repeated = confirmation.get("repeated_ok", False)
    stable = confirmation.get("stable", True)

    # Did a *reflected* canary (not just a behavioural diff) survive to the clean
    # request? That is the strongest proof and the only thing allowed to reach
    # "Confirmed". A differential-only (non-reflective) persistence is real but
    # inherently more coincidence-prone, so it is capped at "Strong".
    reflected_persist = confirmation.get("persisted_reflected")
    if reflected_persist is None:  # legacy record shape (pre-differential)
        reflected_persist = reflected and persisted

    # Rejected: nothing survived clean validation, or unstable noise.
    if not persisted:
        if reflected:
            return 0.40, "Rejected"   # reflected but not cached -> not WCP
        return 0.10, "Rejected"

    # The cache said the clean response came from the origin, so whatever persisted
    # was not served by the cache: origin-side state, not cache poisoning.
    if state == "miss":
        return 0.30, "Rejected"
    if state == "hit" and repeated and stable:
        return (0.97, "Confirmed") if reflected_persist else (0.90, "Strong")
    if state == "hit" and stable:
        return 0.90, "Strong"
    # Silent cache: the hit can only be inferred. Our own canary on a clean request,
    # served again on the repeat read, still carries that inference; a behavioural
    # change does not, and neither does a canary that came back only once.
    if stable and reflected_persist and repeated:
        return 0.82, "Strong"
    return 0.65, "Tentative"


def severity_for_impact(impact: str) -> tuple[str, float]:
    """Map an impact class to (severity, cvss_score). Lowercase severity per schema."""
    impact = (impact or "").lower()
    table = {
        "stored_xss": ("critical", 9.3),
        # Canary cached into an executable script context, breakout unverified.
        "reflected_script": ("high", 7.1),
        "open_redirect": ("high", 7.4),
        "deception": ("high", 7.5),       # private data exposure via cache
        "dos": ("high", 7.5),             # CPDoS
        "reflected": ("medium", 5.3),
        # A cached behaviour change with no attacker-chosen content in it.
        "response_change": ("medium", 5.3),
        "unknown": ("medium", 5.0),
    }
    return table.get(impact, ("medium", 5.0))


def passes_min_confidence(confidence: float, settings: dict) -> bool:
    threshold = float(settings.get("WEB_CACHE_POISON_MIN_CONFIDENCE", 0.8))
    return confidence >= threshold
