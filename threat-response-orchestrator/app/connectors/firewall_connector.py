"""
Firewall Connector (reference implementation)
------------------------------------------------
Adapter for perimeter/NGFW platforms (e.g. Palo Alto Panorama, Fortinet
FortiManager, Cisco Firepower). Blocks IOCs by pushing to a dynamic
address group; ships as a safe simulator by default.
"""
from app.config import get_settings

settings = get_settings()


def _push_to_dynamic_block_list(indicators: list[str]) -> dict:
    return {"status": "simulated_success", "blocked": indicators}


def block_indicators(indicators: list[str]) -> str:
    if not indicators:
        return "No indicators supplied - no firewall action taken."
    resp = _push_to_dynamic_block_list(indicators)
    return f"Blocked {len(indicators)} indicator(s) on perimeter firewall: {', '.join(indicators)} ({resp['status']})."
