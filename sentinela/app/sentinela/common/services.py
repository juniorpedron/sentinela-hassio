"""Traduz dominios/hosts em nomes AMIGAVEIS + categoria.

Usado pelo mapa da rede (/api/graph) para que uma conexao a
``api.anthropic.com`` apareca como "Claude (Anthropic)" na categoria "IA",
em vez de um dominio cru. A categoria vira a cor do no no grafo.
"""

from __future__ import annotations

import ipaddress
from typing import Optional

# (substring no host)  ->  (nome amigavel, categoria)
# A ordem importa: regras mais especificas vem primeiro.
_RULES: list[tuple[str, tuple[str, str]]] = [
    ("anthropic", ("Claude (Anthropic)", "IA")),
    ("claude.ai", ("Claude (Anthropic)", "IA")),
    ("openai", ("ChatGPT (OpenAI)", "IA")),
    ("chatgpt", ("ChatGPT (OpenAI)", "IA")),
    ("oaistatic", ("ChatGPT (OpenAI)", "IA")),
    ("gemini", ("Gemini (Google)", "IA")),
    ("googlevideo", ("YouTube", "Streaming")),
    ("youtube", ("YouTube", "Streaming")),
    ("ytimg", ("YouTube", "Streaming")),
    ("netflix", ("Netflix", "Streaming")),
    ("nflxvideo", ("Netflix", "Streaming")),
    ("spotify", ("Spotify", "Streaming")),
    ("twitch", ("Twitch", "Streaming")),
    ("whatsapp", ("WhatsApp", "Mensagens")),
    ("telegram", ("Telegram", "Mensagens")),
    ("messenger", ("Messenger", "Mensagens")),
    ("instagram", ("Instagram", "Social")),
    ("cdninstagram", ("Instagram", "Social")),
    ("facebook", ("Facebook", "Social")),
    ("fbcdn", ("Facebook", "Social")),
    ("tiktok", ("TikTok", "Social")),
    ("twimg", ("X (Twitter)", "Social")),
    ("twitter", ("X (Twitter)", "Social")),
    ("linkedin", ("LinkedIn", "Social")),
    ("reddit", ("Reddit", "Social")),
    ("githubusercontent", ("GitHub", "Dev")),
    ("github", ("GitHub", "Dev")),
    ("gitlab", ("GitLab", "Dev")),
    ("stackoverflow", ("Stack Overflow", "Dev")),
    ("npmjs", ("npm", "Dev")),
    ("pypi", ("PyPI", "Dev")),
    ("duckduckgo", ("DuckDuckGo", "Busca")),
    ("doubleclick", ("Anuncios / Rastreamento", "Publicidade")),
    ("googlesyndication", ("Anuncios / Rastreamento", "Publicidade")),
    ("googleadservices", ("Anuncios / Rastreamento", "Publicidade")),
    ("google-analytics", ("Anuncios / Rastreamento", "Publicidade")),
    ("googletagmanager", ("Anuncios / Rastreamento", "Publicidade")),
    ("scorecardresearch", ("Anuncios / Rastreamento", "Publicidade")),
    ("adnxs", ("Anuncios / Rastreamento", "Publicidade")),
    ("gstatic", ("Google", "Google")),
    ("googleapis", ("Google", "Google")),
    ("googleusercontent", ("Google", "Google")),
    ("google", ("Google", "Google")),
    ("windowsupdate", ("Windows Update", "Microsoft")),
    ("msftconnecttest", ("Microsoft", "Microsoft")),
    ("msftncsi", ("Microsoft", "Microsoft")),
    ("onedrive", ("OneDrive (Microsoft)", "Microsoft")),
    ("office365", ("Microsoft 365", "Microsoft")),
    ("office", ("Microsoft 365", "Microsoft")),
    ("teams", ("Microsoft Teams", "Microsoft")),
    ("substrate", ("Microsoft 365", "Microsoft")),
    ("live.com", ("Microsoft", "Microsoft")),
    ("windows.com", ("Microsoft", "Microsoft")),
    ("microsoft", ("Microsoft", "Microsoft")),
    ("azure", ("Azure (Microsoft)", "Nuvem")),
    ("bing", ("Bing (Microsoft)", "Microsoft")),
    ("icloud", ("iCloud (Apple)", "Apple")),
    ("mzstatic", ("Apple", "Apple")),
    ("apple", ("Apple", "Apple")),
    ("cloudflare", ("Cloudflare", "Infra")),
    ("cloudfront", ("Amazon CloudFront", "CDN")),
    ("amazonalexa", ("Amazon Alexa", "Nuvem")),
    ("amazonvideo", ("Amazon Prime Video", "Streaming")),
    ("amazonaws", ("Amazon AWS", "Nuvem")),
    ("media-amazon", ("Amazon", "Nuvem")),
    ("amazon", ("Amazon", "Nuvem")),
    ("akamai", ("Akamai (CDN)", "CDN")),
    ("fastly", ("Fastly (CDN)", "CDN")),
    ("mozilla", ("Mozilla / Firefox", "Dev")),
    ("dropbox", ("Dropbox", "Nuvem")),
    ("steam", ("Steam", "Jogos")),
    ("fortiguard", ("Fortinet (VPN)", "Sistema")),
    ("fortinet", ("Fortinet (VPN)", "Sistema")),
    ("ntp.org", ("Relogio (NTP)", "Sistema")),
    ("pool.ntp", ("Relogio (NTP)", "Sistema")),
    ("ntp.br", ("Relogio (NTP)", "Sistema")),
    # --- IoT / casa inteligente ---
    ("crealitycloud", ("Creality (impressora 3D)", "IoT")),
    ("creality", ("Creality (impressora 3D)", "IoT")),
    ("tuya", ("Tuya (casa inteligente)", "IoT")),
    ("shelly", ("Shelly (sensor)", "IoT")),
    ("allterco", ("Shelly (sensor)", "IoT")),
    ("sonoff", ("Sonoff", "IoT")),
    ("ewelink", ("Sonoff (eWeLink)", "IoT")),
    ("a2z.com", ("Amazon / Alexa", "Nuvem")),
    ("aws.dev", ("Amazon (diagnostico)", "Nuvem")),
    # --- vendors ---
    ("samsung", ("Samsung", "Sistema")),
    ("intelbras", ("Intelbras (rede)", "Sistema")),
    ("nvidia", ("Nvidia", "Sistema")),
    ("harman", ("Harman Kardon", "Sistema")),
    # --- infra / sistema ---
    ("in-addr.arpa", ("DNS reverso", "Sistema")),
    ("ip6.arpa", ("DNS reverso", "Sistema")),
    ("home-assistant", ("Home Assistant", "Sistema")),
    ("hass.io", ("Home Assistant", "Sistema")),
    ("digicert", ("Certificados (OCSP)", "Sistema")),
    ("sectigo", ("Certificados (OCSP)", "Sistema")),
    ("letsencrypt", ("Certificados", "Sistema")),
    ("msedge", ("Microsoft (Edge/CDN)", "Microsoft")),
    ("msn.com", ("MSN (Microsoft)", "Microsoft")),
]

_CAT_DEFAULT = "Outro"


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _registrable(host: str) -> str:
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def friendly(host: Optional[str]) -> tuple[str, str]:
    """Devolve (nome_amigavel, categoria) para um host/dominio/IP."""
    if not host:
        return ("Desconhecido", _CAT_DEFAULT)
    h = host.lower().strip().rstrip(".")
    if _is_ip(h):
        return (f"IP {host}", "Desconhecido")
    for chave, (nome, cat) in _RULES:
        if chave in h:
            return (nome, cat)
    reg = _registrable(h)
    return (reg.split(".")[0].capitalize() or reg, _CAT_DEFAULT)
