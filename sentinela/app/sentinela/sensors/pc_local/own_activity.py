"""Coletor de atividade do PROPRIO computador (MODO PC) -- sem Npcap.

Mostra, ao vivo, com quem ESTE computador esta falando e quais dominios ele
resolveu, usando duas fontes que NAO exigem captura de pacotes nem privilegio
de administrador:

  1. Tabela de conexoes do SO via ``psutil`` (IP/porta remota + processo dono,
     ex.: ``chrome.exe`` -> 142.250.x.x). Cada conexao vira um ``flow``.
  2. Cache DNS do Windows (``Get-DnsClientCache``): dominios resolvidos
     recentemente pelo proprio PC. Cada entrada vira um ``dns_query``.

LIMITE (honesto): isto cobre APENAS o trafego do proprio PC. Para ver o
trafego de OUTROS dispositivos e preciso o MODO PI com espelhamento (SPAN).
Uma captura de pacotes de maior fidelidade (DNS/SNI reais de todos) fica
disponivel quando ``scapy`` + Npcap estao presentes -- ver
:func:`packet_capture_available`.
"""

from __future__ import annotations

import asyncio
import csv
import io
import ipaddress
import logging
import socket
import sys
import uuid
from typing import Optional

log = logging.getLogger("sentinela.own_activity")

try:  # psutil e a unica dependencia real deste coletor
    import psutil
except ImportError:  # pragma: no cover - dependencia declarada em requirements-pc.txt
    psutil = None  # type: ignore[assignment]


# Mapa dos tipos de registro DNS numericos que o Get-DnsClientCache devolve.
_DNS_TYPES = {
    "1": "A", "2": "NS", "5": "CNAME", "6": "SOA", "12": "PTR",
    "15": "MX", "16": "TXT", "28": "AAAA", "33": "SRV", "65": "HTTPS",
}


def _map_dns_type(t: Optional[str]) -> str:
    t = (t or "").strip()
    return _DNS_TYPES.get(t, t or "?")


# Portas remotas sensiveis: conexao a essas portas em IP PUBLICO gera alerta.
SUSPECT_PORTS = {
    23: "Telnet", 2323: "Telnet alt", 3389: "RDP", 5900: "VNC", 5901: "VNC",
    445: "SMB", 139: "NetBIOS", 3306: "MySQL", 5432: "Postgres", 1433: "MSSQL",
    6379: "Redis", 27017: "MongoDB", 9200: "Elasticsearch", 11211: "Memcached",
    6667: "IRC", 6697: "IRC/TLS", 4444: "backdoor comum", 1080: "SOCKS proxy",
    9001: "Tor OR", 9030: "Tor Dir", 9050: "Tor SOCKS",
}


def _is_private(ip: str) -> bool:
    """True para IP privado/loopback/link-local (nao alerta destinos internos)."""
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private or a.is_loopback or a.is_link_local
    except ValueError:
        return False


def _normalize_mac(mac: str) -> str:
    return mac.replace("-", ":").lower().strip()


def _primary_ipv4() -> Optional[str]:
    """Descobre o IPv4 usado para sair para a internet (sem enviar nada)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return None
    finally:
        s.close()


def _local_mac_for_ip(ip: Optional[str]) -> Optional[str]:
    """Retorna o MAC da interface que carrega ``ip`` (via psutil)."""
    if psutil is None or not ip:
        return None
    try:
        addrs = psutil.net_if_addrs()
    except Exception:  # pragma: no cover - defensivo
        return None
    for _iface, snics in addrs.items():
        if not any(s.family == socket.AF_INET and s.address == ip for s in snics):
            continue
        for s in snics:
            if s.family == psutil.AF_LINK and s.address:
                return _normalize_mac(s.address)
    return None


def _fallback_mac() -> str:
    """MAC pseudo-estavel a partir de uuid.getnode() (fallback)."""
    n = uuid.getnode()
    return ":".join("%02x" % ((n >> shift) & 0xFF) for shift in range(40, -1, -8))


def packet_capture_available() -> bool:
    """True se scapy + Npcap estiverem prontos para captura de pacotes.

    Quando isto for verdadeiro, uma versao futura pode ligar o sniffer de
    pacotes para obter DNS/SNI reais. Enquanto for falso (ex.: Npcap ausente
    no Windows), o coletor opera so com conexoes + cache DNS.
    """
    try:
        from scapy.arch import get_if_list  # noqa: PLC0415

        return bool(get_if_list())
    except Exception:
        return False


# Cache de reverse-DNS para nao repetir consultas lentas.
_rdns_cache: dict[str, Optional[str]] = {}


async def _rdns(ip: str) -> Optional[str]:
    """Resolve reverso (IP -> host), com cache e timeout curto."""
    if ip in _rdns_cache:
        return _rdns_cache[ip]
    name: Optional[str] = None
    try:
        loop = asyncio.get_running_loop()
        host = await asyncio.wait_for(
            loop.run_in_executor(None, socket.gethostbyaddr, ip), timeout=1.0
        )
        name = host[0]
    except Exception:
        name = None
    _rdns_cache[ip] = name
    return name


def _is_remote_relevante(ip: str) -> bool:
    """Ignora loopback e enderecos nulos; mantem LAN e internet."""
    if not ip or ip in ("0.0.0.0", "::", "::1"):
        return False
    if ip.startswith("127."):
        return False
    return True


async def get_local_identity(storage) -> tuple[str, Optional[str]]:
    """Registra ESTE computador como um dispositivo e devolve (device_id, ip)."""
    ip = _primary_ipv4()
    mac = _local_mac_for_ip(ip) or _fallback_mac()
    hostname = socket.gethostname()
    device_id, _is_new = await storage.upsert_device(mac=mac, hostname=hostname, ip4=ip)
    return device_id, ip


async def sample_connections(
    storage, dev_id: str, local_ip: Optional[str], seen: set, seen_alert: set
) -> int:
    """Registra conexoes NOVAS como fluxos e alerta conexoes a portas sensiveis."""
    if psutil is None:
        return 0
    try:
        loop = asyncio.get_running_loop()
        conns = await loop.run_in_executor(
            None, lambda: psutil.net_connections(kind="inet")
        )
    except Exception as exc:  # pragma: no cover - defensivo (perm no Windows)
        log.debug("net_connections falhou: %s", exc)
        return 0

    novos = 0
    for c in conns:
        if not c.raddr:
            continue
        try:
            rip, rport = c.raddr.ip, c.raddr.port
        except (AttributeError, IndexError):
            continue
        if not _is_remote_relevante(rip):
            continue
        lport = c.laddr.port if c.laddr else None
        key = (lport, rip, rport, int(c.type))
        if key in seen:
            continue
        seen.add(key)

        proto = "tcp" if c.type == socket.SOCK_STREAM else "udp"
        proc = None
        if c.pid:
            try:
                proc = psutil.Process(c.pid).name()
            except Exception:
                proc = None
        host = await _rdns(rip)

        await storage.record_flow(
            device_id=dev_id,
            src_ip=(c.laddr.ip if c.laddr else local_ip),
            src_port=lport,
            dst_ip=rip,
            dst_port=rport,
            proto=proto,
            app_proto=proc,       # nome do processo (ex.: chrome.exe)
            sni=host,             # host por reverse-DNS (aproxima o "com quem")
        )
        novos += 1

        # Alerta: conexao a porta sensivel em destino PUBLICO (fora da LAN).
        if rport in SUSPECT_PORTS and not _is_private(rip):
            akey = (rip, rport)
            if akey not in seen_alert:
                seen_alert.add(akey)
                await storage.add_event(
                    device_id=dev_id,
                    severity="warning",
                    type="port.suspect",
                    title=f"Conexao a porta sensivel {rport} ({SUSPECT_PORTS[rport]})",
                    detail=f"{proc or 'app'} -> {host or rip}:{rport} ({proto})",
                )

    if len(seen) > 5000:  # evita crescer sem limite em sessoes longas
        seen.clear()
    if len(seen_alert) > 2000:
        seen_alert.clear()
    return novos


async def _read_dns_cache() -> list[tuple[str, str, str]]:
    """Le o cache DNS do Windows via Get-DnsClientCache. [] em outros SOs."""
    if not sys.platform.startswith("win"):
        return []
    cmd = [
        "powershell", "-NoProfile", "-NonInteractive", "-Command",
        "Get-DnsClientCache | Select-Object Entry,Type,Data | "
        "ConvertTo-Csv -NoTypeInformation",
    ]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=10.0)
    except Exception as exc:
        log.debug("Get-DnsClientCache falhou: %s", exc)
        return []

    linhas: list[tuple[str, str, str]] = []
    try:
        reader = csv.DictReader(io.StringIO(out.decode(errors="replace")))
        for r in reader:
            nome = (r.get("Entry") or "").strip()
            if not nome:
                continue
            linhas.append((nome, (r.get("Type") or "").strip(), (r.get("Data") or "").strip()))
    except Exception:  # pragma: no cover - parsing defensivo
        pass
    return linhas


async def sample_dns(storage, dev_id: str, local_ip: Optional[str], seen: set) -> int:
    """Registra consultas DNS NOVAS, agregando as respostas por (qname, qtype).

    O cache do Windows lista uma linha por IP de resposta; aqui agrupamos para
    NAO poluir o feed com 15 linhas do mesmo dominio.
    """
    agrupado: dict[tuple[str, str], set[str]] = {}
    for nome, typ, data in await _read_dns_cache():
        chave = (nome, _map_dns_type(typ))
        respostas = agrupado.setdefault(chave, set())
        if data:
            respostas.add(data)

    novos = 0
    for (nome, qtype), respostas in agrupado.items():
        if (nome, qtype) in seen:
            continue
        seen.add((nome, qtype))
        answer = ", ".join(sorted(respostas)[:8]) or None
        await storage.record_dns(
            device_id=dev_id,
            client_ip=local_ip,
            qname=nome,
            qtype=qtype,
            answer=answer,
            blocked=False,
        )
        novos += 1
    if len(seen) > 5000:
        seen.clear()
    return novos


async def run_forever(storage, settings, interval: float = 7.0) -> None:
    """Loop perpetuo de captura da atividade do proprio PC (conexoes + DNS)."""
    if psutil is None:
        log.warning(
            "psutil ausente; captura de atividade do proprio PC desativada "
            "(instale com: pip install psutil)."
        )
        return

    dev_id, local_ip = await get_local_identity(storage)
    log.info(
        "captura de atividade do proprio PC iniciada (host=%s, ip=%s) via "
        "conexoes (psutil) + cache DNS",
        socket.gethostname(),
        local_ip,
    )
    try:
        _pk = await asyncio.wait_for(asyncio.get_running_loop().run_in_executor(None, packet_capture_available), timeout=25)
    except Exception:
        _pk = False
    if not _pk:
        log.info(
            "captura de pacotes (scapy/Npcap) indisponivel -- operando so com "
            "conexoes + cache DNS. Instale o Npcap (https://npcap.com) para "
            "DNS/SNI reais em nivel de pacote."
        )
    # TODO(sentinela): quando packet_capture_available(), ligar um sniffer
    # scapy (AsyncSniffer) para extrair DNS e SNI/JA4 reais dos pacotes.

    seen_conn: set = set()
    seen_dns: set = set()
    seen_alert: set = set()
    while True:
        try:
            nf = await sample_connections(storage, dev_id, local_ip, seen_conn, seen_alert)
            nd = await sample_dns(storage, dev_id, local_ip, seen_dns)
            if nf or nd:
                log.debug("atividade: +%d conexoes, +%d dns", nf, nd)
        except asyncio.CancelledError:
            log.info("captura de atividade cancelada")
            raise
        except Exception as exc:
            log.exception("erro no ciclo de atividade: %s", exc)
        await asyncio.sleep(interval)
