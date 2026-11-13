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
    # --- jogos / consoles ---
    ("playstation", ("PlayStation", "Jogos")),
    ("sonyentertainmentnetwork", ("PlayStation", "Jogos")),
    ("xboxlive", ("Xbox", "Jogos")),
    ("nintendo", ("Nintendo", "Jogos")),
    ("epicgames", ("Epic Games", "Jogos")),
    ("riotgames", ("Riot Games", "Jogos")),
    ("roblox", ("Roblox", "Jogos")),
    # --- streaming / video (BR) ---
    ("disneyplus", ("Disney+", "Streaming")),
    ("disney", ("Disney+", "Streaming")),
    ("hbomax", ("Max (HBO)", "Streaming")),
    ("primevideo", ("Amazon Prime Video", "Streaming")),
    ("aiv-cdn", ("Amazon Prime Video", "Streaming")),
    ("globoplay", ("Globoplay", "Streaming")),
    ("globo.com", ("Globo", "Streaming")),
    ("deezer", ("Deezer", "Streaming")),
    # --- bancos e compras ---
    ("nubank", ("Nubank", "Bancos")),
    ("itau", ("Itau", "Bancos")),
    ("bradesco", ("Bradesco", "Bancos")),
    ("santander", ("Santander", "Bancos")),
    ("bb.com.br", ("Banco do Brasil", "Bancos")),
    ("caixa.gov", ("Caixa", "Bancos")),
    ("bancointer", ("Inter", "Bancos")),
    ("mercadolivre", ("Mercado Livre", "Compras")),
    ("mercadopago", ("Mercado Pago", "Bancos")),
    ("mercadolibre", ("Mercado Livre", "Compras")),
    ("shopee", ("Shopee", "Compras")),
    ("aliexpress", ("AliExpress", "Compras")),
    # --- reunioes / estudo ---
    ("zoom.us", ("Zoom", "Mensagens")),
    ("duolingo", ("Duolingo", "Estudo")),
    ("notion", ("Notion", "Dev")),
    ("slack", ("Slack", "Mensagens")),
    ("discord", ("Discord", "Mensagens")),
    ("signal.org", ("Signal", "Mensagens")),
    # --- telemetria ---
    ("crashlytics", ("Telemetria", "Publicidade")),
    ("app-measurement", ("Telemetria", "Publicidade")),
    ("xiaomi", ("Xiaomi", "IoT")),
    ("smartlife", ("Tuya (casa inteligente)", "IoT")),
    # --- vistos na rede real em 12/11/2026 ---
    ("teamviewer", ("TeamViewer (acesso remoto)", "Trabalho")),
    ("anydesk", ("AnyDesk (acesso remoto)", "Trabalho")),
    ("autodesk", ("Autodesk", "Trabalho")),
    ("cursor.sh", ("Cursor (editor)", "Dev")),
    ("ghcr.io", ("GitHub (imagens)", "Dev")),
    ("docker", ("Docker", "Dev")),
    ("nousresearch", ("Nous Research", "IA")),
    ("perplexity", ("Perplexity", "IA")),
    ("x.ai", ("Grok (xAI)", "IA")),
    ("capcut", ("CapCut", "Social")),
    ("bytedance", ("TikTok / ByteDance", "Social")),
    ("byteoversea", ("TikTok / ByteDance", "Social")),
    ("ibytedtos", ("TikTok / ByteDance", "Social")),
    ("ttwstatic", ("TikTok", "Social")),
    ("wechat", ("WeChat", "Mensagens")),
    ("shein", ("Shein", "Compras")),
    ("susercontent", ("Shopee", "Compras")),
    ("stripe", ("Stripe (pagamentos)", "Bancos")),
    ("intercom", ("Intercom (atendimento)", "Trabalho")),
    ("mailerlite", ("MailerLite", "Trabalho")),
    ("gvt1", ("Google (atualizacoes)", "Google")),
    ("gvt2", ("Google (atualizacoes)", "Google")),
    ("nflxso", ("Netflix", "Streaming")),
    ("nflxext", ("Netflix", "Streaming")),
    ("discomax", ("Max (HBO)", "Streaming")),
    ("lgtvcommon", ("LG TV", "Sistema")),
    ("lgtvsdp", ("LG TV", "Sistema")),
    ("lge.com", ("LG TV", "Sistema")),
    ("alphonso", ("LG TV (medicao de audiencia)", "Publicidade")),
    ("samsungcloud", ("Samsung Cloud", "Nuvem")),
    ("samsungapps", ("Samsung", "Sistema")),
    ("aaplimg", ("Apple", "Apple")),
    ("apple-dns", ("Apple", "Apple")),
    ("akadns", ("Akamai (CDN)", "CDN")),
    ("appsflyer", ("Telemetria", "Publicidade")),
    ("habackup", ("Home Assistant (backup)", "Sistema")),
    ("met.no", ("Previsao do tempo (HA)", "Sistema")),
    ("cdprojektred", ("CD Projekt (jogos)", "Jogos")),
    ("cdpred", ("CD Projekt (jogos)", "Jogos")),
    ("ufsc.br", ("UFSC", "Estudo")),
    ("ufpr.br", ("UFPR", "Estudo")),
    ("conectiva", ("Conectiva", "Outro")),
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
    ("imou", ("Camera Intelbras/Imou (nuvem)", "IoT")),
    ("mibo", ("Camera Intelbras Mibo (nuvem)", "IoT")),
    ("lifeaiot", ("Tuya (casa inteligente)", "IoT")),
    ("iotbing", ("Tuya (casa inteligente)", "IoT")),
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


# Sufixos de dois niveis: em "loja.com.br" o nome e "loja", nao "com".
_TLD2 = {"com.br", "org.br", "net.br", "gov.br", "edu.br", "jus.br", "mil.br", "art.br", "blog.br",
         "co.uk", "org.uk", "com.ar", "com.mx", "com.pt", "co.jp", "com.au", "com.cn", "co.in"}

# Enderecos conhecidos que aparecem sem nome.
_IPS_CONHECIDOS = {
    "1.1.1.1": ("Cloudflare DNS", "Sistema"), "1.0.0.1": ("Cloudflare DNS", "Sistema"),
    "8.8.8.8": ("Google DNS", "Sistema"), "8.8.4.4": ("Google DNS", "Sistema"),
    "9.9.9.9": ("Quad9 DNS", "Sistema"),
    "2606:4700:4700::1111": ("Cloudflare DNS", "Sistema"), "2001:4860:4860::8888": ("Google DNS", "Sistema"),
    "2804:14d:1:0:181:213:132:4": ("DNS da Claro", "Sistema"),
    "2804:14d:1:0:181:213:132:5": ("DNS da Claro", "Sistema"),
}


def _registrable(host: str) -> str:
    parts = host.split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in _TLD2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def friendly(host: Optional[str]) -> tuple[str, str]:
    """Devolve (nome_amigavel, categoria) para um host/dominio/IP."""
    if not host:
        return ("Desconhecido", _CAT_DEFAULT)
    h = host.lower().strip().rstrip(".")
    if _is_ip(h):
        return _IPS_CONHECIDOS.get(h, (f"IP {host}", "Sem nome"))
    for chave, (nome, cat) in _RULES:
        if chave in h:
            return (nome, cat)
    reg = _registrable(h)
    return (reg.split(".")[0].capitalize() or reg, _CAT_DEFAULT)
