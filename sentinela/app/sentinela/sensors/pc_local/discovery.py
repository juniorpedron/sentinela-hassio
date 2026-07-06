"""Descoberta ativa da rede local para o MODO PC (portatil/standalone).

Este modulo faz DESCOBERTA ATIVA da rede onde o notebook esta conectado,
sem depender de captura promiscua nem de Npcap. As tecnicas usadas:

  * Tabela ARP do sistema operacional (vizinhanca L2 ja conhecida pelo SO).
  * Ping sweep no LAN_CIDR (popula/atualiza a tabela ARP e revela hosts vivos).
  * mDNS (5353) via zeroconf/ServiceBrowser em servicos comuns.
  * SSDP (1900) via M-SEARCH UDP (UPnP/DLNA/roteadores/TVs).
  * Reverse DNS para tentar um hostname a partir do IP.
  * Fabricante (OUI) a partir do MAC via mac-vendor-lookup.

LIMITE HONESTO DO MODO PC
-------------------------
Num switch/AP WiFi comum, este processo enxerga apenas:
  - o proprio trafego do notebook;
  - trafego de broadcast/multicast (ARP, mDNS, SSDP, DHCP...);
  - o que ele mesmo provoca ativamente (ping sweep, M-SEARCH, queries mDNS).
NAO enxerga o conteudo unicast de outros dispositivos entre si -- para isso e
necessario o MODO PI com espelhamento de porta (SPAN). Toda descoberta aqui e
"best effort" e degrada com elegancia quando falta permissao ou biblioteca.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
import socket
import struct
import sys
from typing import Iterable

log = logging.getLogger("sentinela.discovery")

# --- Dependencias opcionais (degradar com elegancia se ausentes) -------------
try:  # OUI/fabricante a partir do MAC
    from mac_vendor_lookup import AsyncMacLookup  # type: ignore

    _HAS_MAC_LOOKUP = True
except Exception:  # pragma: no cover - ambiente sem a lib
    AsyncMacLookup = None  # type: ignore
    _HAS_MAC_LOOKUP = False

try:  # mDNS via zeroconf
    from zeroconf import ServiceStateChange  # type: ignore
    from zeroconf.asyncio import AsyncServiceBrowser, AsyncZeroconf  # type: ignore

    _HAS_ZEROCONF = True
except Exception:  # pragma: no cover - ambiente sem a lib
    _HAS_ZEROCONF = False


# Servicos mDNS comuns em redes domesticas (TVs, casts, impressoras, AirPlay...)
MDNS_SERVICES = [
    "_http._tcp.local.",
    "_googlecast._tcp.local.",
    "_airplay._tcp.local.",
    "_printer._tcp.local.",
    "_ipp._tcp.local.",
    "_raop._tcp.local.",
]

# Regex para extrair pares IP/MAC das varias saidas de tabela ARP por SO.
_MAC_RE = re.compile(r"([0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5})")
_IP_RE = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")


def _normalize_mac(mac: str) -> str:
    """Normaliza um MAC para o formato aa:bb:cc:dd:ee:ff minusculo."""
    mac = mac.replace("-", ":").lower().strip()
    parts = mac.split(":")
    if len(parts) == 6:
        parts = [p.zfill(2) for p in parts]
        return ":".join(parts)
    return mac


def _is_valid_mac(mac: str) -> bool:
    """True se o MAC for utilizavel (nao nulo/broadcast/multicast).

    Rejeita tambem enderecos de grupo/multicast: quando o bit menos
    significativo do primeiro octeto esta setado (octeto impar), o MAC e um
    endereco de grupo -- cobre IPv4 multicast (01:00:5e:*), IPv6 multicast
    (33:33:*) e STP (01:80:c2:*), que o `arp -a` do Windows lista como
    entradas estaticas e nao sao dispositivos reais.
    """
    if not mac or mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
        return False
    if not _MAC_RE.fullmatch(mac):
        return False
    try:
        first_octet = int(mac.split(":")[0], 16)
    except ValueError:
        return False
    if first_octet & 0x01:  # bit de grupo/multicast setado
        return False
    return True


async def _run(cmd: list[str], timeout: float = 10.0) -> str:
    """Executa um comando externo e devolve stdout (str), tolerando falhas."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return out.decode(errors="replace")
    except (FileNotFoundError, asyncio.TimeoutError, OSError) as exc:
        log.debug("comando falhou (%s): %s", " ".join(cmd), exc)
        return ""


async def read_arp_table() -> dict[str, str]:
    """Le a tabela ARP do SO e devolve {ip: mac_normalizado}.

    Suporta Windows (arp -a), Linux (ip neigh / arp -an) e macOS (arp -an).
    Degrada para dicionario vazio se nenhuma ferramenta estiver disponivel.
    """
    result: dict[str, str] = {}

    if sys.platform.startswith("win"):
        candidates = [["arp", "-a"]]
    elif sys.platform == "darwin":
        candidates = [["arp", "-an"]]
    else:  # Linux e afins
        candidates = [["ip", "neigh"], ["arp", "-an"]]

    text = ""
    for cmd in candidates:
        text = await _run(cmd)
        if text.strip():
            break

    for line in text.splitlines():
        mac_m = _MAC_RE.search(line)
        ip_m = _IP_RE.search(line)
        if not (mac_m and ip_m):
            continue
        mac = _normalize_mac(mac_m.group(1))
        ip = ip_m.group(1)
        if _is_valid_mac(mac):
            result[ip] = mac
    log.debug("ARP: %d entradas", len(result))
    return result


async def _ping_one(ip: str, timeout: float = 1.0) -> bool:
    """Dispara um unico ping ICMP no host. True se respondeu."""
    if sys.platform.startswith("win"):
        cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(int(max(1, timeout))), ip]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        rc = await asyncio.wait_for(proc.wait(), timeout=timeout + 2.0)
        return rc == 0
    except (FileNotFoundError, asyncio.TimeoutError, OSError):
        return False


async def ping_sweep(cidr: str, concurrency: int = 64) -> list[str]:
    """Faz ping sweep no CIDR e devolve a lista de IPs que responderam.

    Serve principalmente para POPULAR a tabela ARP (mesmo que o host bloqueie
    ICMP, o ARP costuma ficar cacheado). Limita a /22 para nao explodir.
    """
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        log.warning("LAN_CIDR invalido: %s", cidr)
        return []

    hosts = list(net.hosts())
    if len(hosts) > 1024:
        log.warning(
            "LAN_CIDR %s tem %d hosts; limitando ping sweep aos 1024 primeiros",
            cidr,
            len(hosts),
        )
        hosts = hosts[:1024]

    sem = asyncio.Semaphore(concurrency)
    alive: list[str] = []

    async def _task(ip: str) -> None:
        async with sem:
            if await _ping_one(ip):
                alive.append(ip)

    await asyncio.gather(*(_task(str(ip)) for ip in hosts))
    log.debug("ping sweep %s: %d hosts vivos", cidr, len(alive))
    return alive


async def reverse_dns(ip: str) -> str | None:
    """Resolve reverse DNS (PTR) para o IP, sem bloquear o event loop."""
    loop = asyncio.get_running_loop()
    try:
        host, _, _ = await loop.run_in_executor(
            None, socket.gethostbyaddr, ip
        )
        return host or None
    except (socket.herror, socket.gaierror, OSError):
        return None


async def ssdp_discover(timeout: float = 3.0) -> set[str]:
    """Descoberta SSDP (UPnP) via M-SEARCH multicast em 239.255.255.250:1900.

    Devolve o conjunto de IPs que responderam. Degrada para conjunto vazio se
    o socket UDP nao puder ser criado (permissao/firewall).
    """
    msg = (
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        'MAN: "ssdp:discover"\r\n'
        "MX: 2\r\n"
        "ST: ssdp:all\r\n"
        "\r\n"
    ).encode("ascii")

    found: set[str] = set()
    loop = asyncio.get_running_loop()

    def _blocking_search() -> set[str]:
        ips: set[str] = set()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.setsockopt(
                socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, struct.pack("b", 2)
            )
            sock.settimeout(timeout)
            sock.sendto(msg, ("239.255.255.250", 1900))
            import time

            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                try:
                    _, addr = sock.recvfrom(2048)
                    ips.add(addr[0])
                except socket.timeout:
                    break
                except OSError:
                    break
            sock.close()
        except OSError as exc:
            log.debug("SSDP indisponivel: %s", exc)
        return ips

    try:
        found = await loop.run_in_executor(None, _blocking_search)
    except Exception as exc:  # pragma: no cover
        log.debug("SSDP falhou: %s", exc)
    log.debug("SSDP: %d respostas", len(found))
    return found


async def mdns_discover(timeout: float = 4.0) -> dict[str, str]:
    """Descoberta mDNS via zeroconf; devolve {ip: hostname}.

    Faz browse dos servicos em MDNS_SERVICES por alguns segundos. Degrada para
    dicionario vazio se a lib zeroconf nao estiver instalada.
    """
    if not _HAS_ZEROCONF:
        log.debug("zeroconf ausente; mDNS desabilitado")
        return {}

    discovered: dict[str, str] = {}
    azc = AsyncZeroconf()

    def _on_change(zeroconf, service_type, name, state_change):  # noqa: ANN001
        if state_change is not ServiceStateChange.Added:
            return
        # Agenda a resolucao do servico sem bloquear o callback.
        asyncio.ensure_future(_resolve(zeroconf, service_type, name))

    async def _resolve(zeroconf, service_type, name):  # noqa: ANN001
        try:
            from zeroconf.asyncio import AsyncServiceInfo  # type: ignore

            info = AsyncServiceInfo(service_type, name)
            await info.async_request(zeroconf, 3000)
            if not info:
                return
            hostname = (info.server or name).rstrip(".")
            for addr in info.parsed_addresses():
                if ":" not in addr:  # apenas IPv4 aqui
                    discovered[addr] = hostname
        except Exception as exc:  # pragma: no cover
            log.debug("mDNS resolve falhou (%s): %s", name, exc)

    browsers = []
    try:
        for svc in MDNS_SERVICES:
            browsers.append(
                AsyncServiceBrowser(
                    azc.zeroconf, svc, handlers=[_on_change]
                )
            )
        await asyncio.sleep(timeout)
    except Exception as exc:  # pragma: no cover
        log.debug("mDNS browse falhou: %s", exc)
    finally:
        for b in browsers:
            try:
                await b.async_cancel()
            except Exception:
                pass
        try:
            await azc.async_close()
        except Exception:
            pass

    log.debug("mDNS: %d hosts", len(discovered))
    return discovered


class _VendorResolver:
    """Wrapper preguicoso para lookup de fabricante (OUI), tolerante a falhas."""

    def __init__(self) -> None:
        self._lookup = None

    async def resolve(self, mac: str) -> str | None:
        if not _HAS_MAC_LOOKUP:
            return None
        if self._lookup is None:
            try:
                self._lookup = AsyncMacLookup()
            except Exception:  # pragma: no cover
                return None
        try:
            return await self._lookup.lookup(mac)
        except Exception:
            # MAC desconhecido na base local ou base ausente.
            return None


async def discover_once(storage, settings, vendor: _VendorResolver) -> int:
    """Executa UM ciclo completo de descoberta e persiste no storage.

    Retorna o numero de dispositivos (novos ou atualizados) processados.
    Cada host descoberto vira um upsert_device; hosts novos ja geram o evento
    device.new dentro do storage. Aqui adicionamos ainda um evento informativo
    de descoberta ativa por ciclo, se algo novo aparecer.
    """
    # 1) Ping sweep primeiro para popular a tabela ARP, depois le o ARP.
    await ping_sweep(settings.lan_cidr)
    arp = await read_arp_table()

    # 2) Descobertas paralelas de camada de aplicacao.
    mdns_task = asyncio.create_task(mdns_discover())
    ssdp_task = asyncio.create_task(ssdp_discover())
    mdns_hosts, ssdp_ips = await asyncio.gather(mdns_task, ssdp_task)

    # 3) Consolida por IP. So conseguimos MAC para hosts na tabela ARP (mesma
    #    L2). IPs vistos apenas por SSDP/mDNS sem MAC no ARP sao ignorados como
    #    device (nao ha chave 'mac' confiavel), mas ficam registrados via ARP na
    #    proxima rodada se responderem ao proximo sweep.
    processed = 0
    novos = 0

    for ip, mac in arp.items():
        hostname = mdns_hosts.get(ip)
        if not hostname:
            hostname = await reverse_dns(ip)
        mac_vendor = await vendor.resolve(mac)

        try:
            device_id, is_new = await storage.upsert_device(
                mac=mac,
                mac_vendor=mac_vendor,
                hostname=hostname,
                ip4=ip,
            )
        except Exception as exc:
            log.warning("upsert_device falhou para %s/%s: %s", ip, mac, exc)
            continue

        processed += 1
        if is_new:
            novos += 1

        # Enriquecimento: se o IP tambem respondeu a SSDP, registra um evento
        # informativo (indica servico UPnP ativo naquele host).
        if ip in ssdp_ips:
            try:
                await storage.add_event(
                    device_id=device_id,
                    severity="info",
                    type="discovery.ssdp",
                    title="Servico UPnP/SSDP detectado",
                    detail=f"{ip} respondeu ao M-SEARCH SSDP (porta 1900).",
                )
            except Exception:
                pass

    if novos:
        try:
            await storage.add_event(
                severity="info",
                type="discovery.sweep",
                title="Descoberta ativa concluida",
                detail=(
                    f"{novos} dispositivo(s) novo(s) e {processed} host(s) "
                    f"processado(s) no CIDR {settings.lan_cidr}."
                ),
            )
        except Exception:
            pass

    log.info(
        "ciclo de descoberta: %d host(s) processado(s), %d novo(s)",
        processed,
        novos,
    )
    return processed


async def run_forever(storage, settings, interval: float = 60.0) -> None:
    """Loop perpetuo de descoberta ativa para o MODO PC.

    Roda um ciclo, dorme `interval` segundos e repete. Nunca derruba o processo
    por causa de um erro pontual num ciclo -- apenas loga e tenta de novo.

    LIMITE: mesmo com todos os metodos combinados, o MODO PC so ve o proprio
    trafego + broadcast/multicast + o que descobre ativamente. Conteudo unicast
    entre outros dispositivos exige o MODO PI (SPAN).
    """
    vendor = _VendorResolver()
    log.info(
        "descoberta ativa iniciada (CIDR=%s, intervalo=%ss); "
        "MODO PC ve apenas broadcast/multicast + descoberta ativa",
        settings.lan_cidr,
        int(interval),
    )
    while True:
        try:
            await discover_once(storage, settings, vendor)
        except asyncio.CancelledError:
            log.info("descoberta ativa cancelada")
            raise
        except Exception as exc:
            log.exception("erro no ciclo de descoberta: %s", exc)
        try:
            await asyncio.sleep(interval)
        except asyncio.CancelledError:
            log.info("descoberta ativa cancelada")
            raise
