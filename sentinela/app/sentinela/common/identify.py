"""Identificacao de dispositivos: nome de exibicao, tipo e pistas de sistema.

Junta as pistas que o Sentinela consegue ver (rotulo dado pelo usuario, nome
DHCP, mDNS/SSDP, fabricante do MAC, User-Agent HTTP, classe DHCP) e devolve um
nome legivel e um TIPO (computador, celular, tv, ...). Tudo aqui e heuristica:
o campo ``kind_source`` diz de onde veio o palpite.

Funcoes puras (sem I/O) para poderem ser testadas isoladamente.
"""

from __future__ import annotations

import ipaddress
import json
import re
from typing import Any, Optional

# tipo -> (rotulo PT-BR, grupo do mapa)
KINDS: dict[str, tuple[str, str]] = {
    "router": ("Roteador / rede", "Rede"),
    "server": ("Servidor", "Rede"),
    "computer": ("Computador", "Computadores"),
    "phone": ("Celular", "Celulares"),
    "tablet": ("Tablet", "Celulares"),
    "watch": ("Relogio", "Celulares"),
    "tv": ("TV / streaming", "TV & Mídia"),
    "console": ("Videogame", "TV & Mídia"),
    "speaker": ("Caixa de som / assistente", "Voz"),
    "printer": ("Impressora", "IoT"),
    "camera": ("Camera", "IoT"),
    "iot": ("Casa inteligente", "IoT"),
    "unknown": ("Nao identificado", "Outros"),
}

# (regex, tipo). A ordem importa: mais especifico primeiro.
_TEXT_RULES: list[tuple[str, str]] = [
    (r"apple ?watch|\bwatch\b|galaxy ?watch|mi ?band|amazfit", "watch"),
    (r"ipad|\btablet\b|galaxy ?tab|kindle|fire hd", "tablet"),
    (r"iphone|android|galaxy|\bpixel\b|redmi|xiaomi|motorola|\bmoto\b|celular|oneplus|huawei p|poco", "phone"),
    (r"playstation|\bps[345]\b|xbox|nintendo|switch|steam ?deck", "console"),
    (r"alexa|\becho\b|homepod|google ?home|nest ?(mini|hub|audio)|sonos|receiver|\bavr\b|soundbar|harman|denon|yamaha", "speaker"),
    (r"\btv\b|firetv|fire ?tv|chromecast|roku|apple ?tv|webos|tizen|bravia|smart ?tv|android ?tv|mi ?box", "tv"),
    (r"impressora|printer|creality|\bepson\b|\bhp ?(ink|laser|desk|office)|brother|canon", "printer"),
    (r"camera|c[aâ]mera|\bcam\b|intelbras ?(ic|im)|\bic[0-9]\b|hikvision|dahua|reolink|tapo c", "camera"),
    (r"shelly|tuya|positivo|sonoff|ewelink|\besp(32|8266)?\b|espressif|tasmota|controle|sensor|l[aâ]mpada|\bplug\b|tomada|smart ?life|ekaza|broadlink", "iot"),
    (r"twibi|modem|roteador|router|gateway|mesh|access ?point|\bap\b|mikrotik|ubiquiti|unifi|tp-?link|d-?link|huawei|zte|arris|intelbras", "router"),
    (r"raspberry|\bpi\b|home ?assistant|hass|\bnas\b|synology|servidor|server|proxmox", "server"),
    (r"macbook|imac|mac ?(mini|pro|studio)|\bpc\b|notebook|laptop|desktop|thinkpad|omen|\basus\b|\bdell\b|lenovo|windows|surface", "computer"),
]

# Fabricante (OUI) -> tipo provavel quando nada mais ajuda.
_VENDOR_RULES: list[tuple[str, str]] = [
    (r"sony interactive|nintendo|microsoft xbox", "console"),
    (r"amazon tech", "speaker"),
    (r"espressif|tuya|shelly|allterco|shenzhen|hangzhou|sonoff|itead|bouffalo|beken|realtek semi", "iot"),
    (r"raspberry", "server"),
    (r"lg electronics|samsung electronics|tcl|hisense|roku|vizio", "tv"),
    (r"google", "tv"),
    (r"hewlett|\bhp\b|dell|lenovo|asustek|azurewave|intel corp|micro-star|giga-byte|liteon", "computer"),
    (r"huawei|tp-link|d-link|zte|arris|intelbras|mikrotik|ubiquiti|tenda|multilaser", "router"),
    (r"harman|sonos|bose|denon", "speaker"),
    (r"creality|epson|brother|canon", "printer"),
    (r"apple", "phone"),
]

_UA_RULES: list[tuple[str, str, str]] = [
    (r"iphone", "phone", "iOS"),
    (r"ipad", "tablet", "iPadOS"),
    (r"watch ?os", "watch", "watchOS"),
    (r"apple ?tv|tvos", "tv", "tvOS"),
    (r"playstation", "console", "PlayStation"),
    (r"xbox", "console", "Xbox"),
    (r"nintendo", "console", "Nintendo"),
    (r"web0s|webos|tizen|smart-?tv|bravia|roku|crkey|aft[a-z]", "tv", "Smart TV"),
    (r"android", "phone", "Android"),
    (r"windows nt", "computer", "Windows"),
    (r"mac os x|macintosh|darwin", "computer", "macOS"),
    (r"cros", "computer", "ChromeOS"),
    (r"linux", "computer", "Linux"),
]


def is_private_mac(mac: Optional[str]) -> bool:
    """True se o MAC e 'localmente administrado' (MAC privado/aleatorio)."""
    try:
        return bool(int(str(mac).split(":")[0], 16) & 0x02)
    except (ValueError, IndexError, AttributeError):
        return False


def is_ip_like(name: Optional[str]) -> bool:
    """True se o 'nome' e so um endereco IP (v4/v6) -- nao serve como nome."""
    if not name:
        return False
    s = str(name).strip().rstrip(".")
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return bool(re.fullmatch(r"[0-9.\-]+(\.in-addr\.arpa)?", s))


def clean_hostname(name: Optional[str]) -> Optional[str]:
    """Normaliza um hostname; devolve None se for vazio ou so um IP."""
    if not name:
        return None
    s = str(name).strip().rstrip(".")
    for suf in (".local", ".lan", ".home", ".localdomain"):
        if s.lower().endswith(suf):
            s = s[: -len(suf)]
    if not s or is_ip_like(s):
        return None
    return s


def parse_meta(raw: Any) -> dict:
    """Le a coluna ``meta`` (JSON em texto) como dict; tolera lixo."""
    if isinstance(raw, dict):
        return raw
    if not raw:
        return {}
    try:
        val = json.loads(raw)
        return val if isinstance(val, dict) else {}
    except (ValueError, TypeError):
        return {}


def os_from_dhcp(vendor_class: Optional[str], params: Optional[str]) -> Optional[str]:
    """Palpite de sistema a partir da classe DHCP (opcao 60) e da lista 55."""
    v = (vendor_class or "").lower()
    if v.startswith("msft"):
        return "Windows"
    if v.startswith("android-dhcp"):
        return "Android"
    if v.startswith("dhcpcd"):
        return "Linux/Android"
    if v.startswith("udhcp"):
        return "Linux embarcado"
    if "ps4" in v or "ps5" in v or "playstation" in v:
        return "PlayStation"
    p = (params or "").replace(" ", "")
    if not v and p.startswith("1,121,3,6,15,119,252"):
        return "Apple (iOS/macOS)"
    return None


def os_from_ua(ua: Optional[str]) -> tuple[Optional[str], Optional[str]]:
    """(tipo, sistema) a partir de um User-Agent HTTP."""
    s = (ua or "").lower()
    if not s:
        return None, None
    for rx, kind, osname in _UA_RULES:
        if re.search(rx, s):
            return kind, osname
    return None, None


def guess_kind(dev: dict) -> tuple[str, str]:
    """Devolve (tipo, origem_do_palpite) para um registro de dispositivo."""
    meta = parse_meta(dev.get("meta"))
    label = (dev.get("label") or "").lower()
    names = " ".join(
        str(x) for x in (clean_hostname(dev.get("hostname")), meta.get("dhcp_name")) if x
    ).lower()

    for text, origem in ((label, "rotulo"), (names, "nome na rede")):
        if text:
            for rx, kind in _TEXT_RULES:
                if re.search(rx, text):
                    return kind, origem

    kind_ua, _os = os_from_ua(meta.get("ua"))
    if kind_ua:
        return kind_ua, "navegador (User-Agent)"

    osname = (meta.get("os") or "").lower()
    if "windows" in osname:
        return "computer", "DHCP"
    if "android" in osname:
        return "phone", "DHCP"
    if "playstation" in osname:
        return "console", "DHCP"
    if "embarcado" in osname:
        return "iot", "DHCP"

    vendor = (dev.get("mac_vendor") or "").lower()
    if vendor:
        for rx, kind in _VENDOR_RULES:
            if re.search(rx, vendor):
                return kind, "fabricante"

    if "apple" in osname:
        return "phone", "DHCP"
    if is_private_mac(dev.get("mac")):
        # MAC privado e tipico de celular/tablet/notebook moderno.
        return "phone", "MAC privado"
    return "unknown", "sem pistas"


def display_name(dev: dict) -> str:
    """Melhor nome disponivel: rotulo > nome DHCP > hostname > tipo + final do IP/MAC."""
    if dev.get("label"):
        return str(dev["label"])
    meta = parse_meta(dev.get("meta"))
    for cand in (meta.get("dhcp_name"), clean_hostname(dev.get("hostname"))):
        if cand:
            return str(cand)
    kind, _ = guess_kind(dev)
    base = KINDS.get(kind, KINDS["unknown"])[0] if kind != "unknown" else "Dispositivo"
    vendor = (dev.get("mac_vendor") or "").split(",")[0].split(" ")[0]
    if vendor and kind in ("unknown", "iot", "computer", "router"):
        base = f"{base} {vendor}"
    ip = dev.get("ip4") or ""
    if ip:
        return f"{base} (.{ip.split('.')[-1]})"
    mac = dev.get("mac") or ""
    return f"{base} ({mac[-5:]})" if mac else base


def is_internal(dev: dict, lan_net: Optional[ipaddress._BaseNetwork]) -> bool:
    """True para 'dispositivos' que nao sao da LAN (ex.: rede docker do HA)."""
    ip = dev.get("ip4")
    if not ip or lan_net is None:
        return False
    try:
        return ipaddress.ip_address(ip) not in lan_net
    except ValueError:
        return False


def enrich(dev: dict, lan_net: Optional[ipaddress._BaseNetwork] = None) -> dict:
    """Copia do registro com os campos derivados usados pela API/painel."""
    out = dict(dev)
    meta = parse_meta(dev.get("meta"))
    kind, origem = guess_kind(dev)
    _k, os_ua = os_from_ua(meta.get("ua"))
    out["meta"] = meta
    out["display_name"] = display_name(dev)
    out["kind"] = kind
    out["kind_label"] = KINDS.get(kind, KINDS["unknown"])[0]
    out["kind_group"] = KINDS.get(kind, KINDS["unknown"])[1]
    out["kind_source"] = origem
    out["os"] = os_ua or meta.get("os")
    out["private_mac"] = is_private_mac(dev.get("mac"))
    out["internal"] = is_internal(dev, lan_net)
    out["named"] = bool(dev.get("label") or meta.get("dhcp_name") or clean_hostname(dev.get("hostname")))
    return out


# ---------------------------------------------------------------------------
# Um aparelho, varios MACs
# ---------------------------------------------------------------------------
# Celulares usam "MAC privado", que pode mudar (por rede, por tempo, ao esquecer
# a rede). Cada MAC novo vira um registro novo no banco. Aqui juntamos os
# registros que sao o MESMO aparelho, sem apagar nada:
#   1. vinculo manual: meta.alias_of = id do registro principal;
#   2. automatico: mesmo nome DHCP (nao generico), com pelo menos um MAC
#      privado, e sem os dois terem ficado ativos ao mesmo tempo.

# Nomes de fabrica: dois aparelhos diferentes costumam ter o mesmo.
_NOMES_GENERICOS = {
    "iphone", "ipad", "ipod", "macbook", "macbook-air", "macbook-pro", "imac", "watch",
    "apple-watch", "android", "galaxy", "localhost", "unknown", "espressif", "wlan0",
    "host", "device", "phone", "celular", "tablet", "tv", "smart-tv", "desktop", "laptop", "pc",
}


def _dt(v):
    from datetime import datetime, timezone

    try:
        d = datetime.fromisoformat(str(v))
    except (ValueError, TypeError):
        return None
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def _sobrepoe(a: dict, b: dict, folga_h: float = 24.0) -> bool:
    """Os dois registros ficaram ativos ao mesmo tempo (por mais que a folga)?"""
    a1, a2, b1, b2 = _dt(a.get("first_seen")), _dt(a.get("last_seen")), _dt(b.get("first_seen")), _dt(b.get("last_seen"))
    if None in (a1, a2, b1, b2):
        return False
    ini, fim = max(a1, b1), min(a2, b2)
    return (fim - ini).total_seconds() > folga_h * 3600


def chave_nome(dev: dict) -> Optional[str]:
    """Nome DHCP normalizado, se servir para reconhecer o aparelho; senao None."""
    nome = (parse_meta(dev.get("meta")).get("dhcp_name") or "").strip().lower()
    if len(nome) < 4 or nome in _NOMES_GENERICOS or is_ip_like(nome):
        return None
    return nome


def agrupar(devs: list[dict]) -> tuple[list[dict], dict[str, str]]:
    """Junta registros do mesmo aparelho.

    Devolve (lista de aparelhos, mapa id_do_registro -> id_do_aparelho). Cada
    aparelho e uma copia do registro principal com os dados de rede (mac, ip,
    ultimo visto) do registro visto por ultimo, mais ``members``.
    """
    por_id = {d["id"]: d for d in devs}
    pai: dict[str, str] = {d["id"]: d["id"] for d in devs}

    def raiz(i: str) -> str:
        visto = set()
        while pai.get(i, i) != i and i not in visto:
            visto.add(i)
            i = pai[i]
        return i

    # 1) vinculo manual
    for d in devs:
        alvo = parse_meta(d.get("meta")).get("alias_of")
        if alvo and alvo in por_id and alvo != d["id"] and raiz(alvo) != d["id"]:
            pai[d["id"]] = alvo

    # 2) automatico pelo nome DHCP
    por_nome: dict[str, list[dict]] = {}
    for d in devs:
        k = chave_nome(d)
        if k:
            por_nome.setdefault(k, []).append(d)
    for membros in por_nome.values():
        if len(membros) < 2 or not any(is_private_mac(m.get("mac")) for m in membros):
            continue
        membros.sort(key=lambda m: str(m.get("first_seen") or ""))
        base = membros[0]
        aceitos = [base]
        for m in membros[1:]:
            if any(_sobrepoe(m, a) for a in aceitos):
                continue                      # ativos ao mesmo tempo: aparelhos distintos
            aceitos.append(m)
            if raiz(m["id"]) != raiz(base["id"]):
                pai[raiz(m["id"])] = raiz(base["id"])

    grupos: dict[str, list[dict]] = {}
    for d in devs:
        grupos.setdefault(raiz(d["id"]), []).append(d)

    saida: list[dict] = []
    mapa: dict[str, str] = {}
    for _r, membros in grupos.items():
        membros.sort(key=lambda m: str(m.get("last_seen") or ""), reverse=True)
        recente = membros[0]
        # principal: quem tem rotulo (o mais antigo deles) > alvo do vinculo manual > o mais antigo.
        # Assim nao importa em que sentido o usuario vinculou: o aparelho "conhecido" manda.
        rotulados = sorted((m for m in membros if m.get("label")), key=lambda m: str(m.get("first_seen") or ""))
        if rotulados:
            principal = rotulados[0]
        elif any(parse_meta(m.get("meta")).get("alias_of") for m in membros):
            principal = por_id[_r]
        else:
            principal = min(membros, key=lambda m: str(m.get("first_seen") or ""))
        ap = dict(principal)
        meta: dict = {}
        for m in reversed(membros):            # o mais recente sobrescreve
            meta.update({k: v for k, v in parse_meta(m.get("meta")).items() if v and k != "alias_of"})
        ap["meta"] = meta
        for campo in ("mac", "ip4", "ip6", "last_seen"):
            ap[campo] = recente.get(campo) or principal.get(campo)
        ap["mac_vendor"] = recente.get("mac_vendor") or principal.get("mac_vendor")
        ap["hostname"] = clean_hostname(recente.get("hostname")) or clean_hostname(principal.get("hostname")) or recente.get("hostname")
        ap["first_seen"] = min(str(m.get("first_seen") or "") for m in membros) or principal.get("first_seen")
        if not ap.get("label") and rotulados:
            ap["label"] = rotulados[0]["label"]
        # confianca do aparelho: quarentena em qualquer MAC prevalece; senao, confiavel se algum for.
        if any(m.get("trust_state") == "quarantine" for m in membros):
            ap["trust_state"] = "quarantine"
        elif any(m.get("trust_state") == "trusted" for m in membros):
            ap["trust_state"] = "trusted"
        ap["members"] = [
            {"id": m["id"], "mac": m.get("mac"), "ip4": m.get("ip4"), "first_seen": m.get("first_seen"),
             "last_seen": m.get("last_seen"), "manual": bool(parse_meta(m.get("meta")).get("alias_of")),
             "principal": m["id"] == principal["id"]}
            for m in membros
        ]
        for m in membros:
            mapa[m["id"]] = principal["id"]
        saida.append(ap)
    saida.sort(key=lambda a: str(a.get("last_seen") or ""), reverse=True)
    return saida, mapa
