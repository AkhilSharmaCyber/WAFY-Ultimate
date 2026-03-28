"""Static threat intelligence — known bad IPs and scanning tool signatures."""

BAD_IPS = {
    "185.220.101.1",   # known TOR exit node (example)
    "45.33.32.156",    # known scanner
    "89.248.167.131",
    "193.32.162.157",
}

KNOWN_TOOLS = [
    "sqlmap",
    "nmap",
    "masscan",
    "nikto",
    "dirbuster",
    "gobuster",
    "wfuzz",
    "burpsuite",
    "acunetix",
    "appscan",
    "w3af",
    "havij",
    "metasploit",
]


def is_bad_ip(ip: str) -> bool:
    return ip in BAD_IPS


def is_known_tool(payload: str) -> bool:
    lower = payload.lower()
    return any(tool in lower for tool in KNOWN_TOOLS)
