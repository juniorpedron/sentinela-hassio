"""Ouvinte PASSIVO de multicast (MODO PC) -- sem Npcap, sem MITM.

Escuta os grupos multicast onde os dispositivos da rede se ANUNCIAM
espontaneamente e colhe nomes/modelos/servicos -- ou seja, captura os pacotes
que os OUTROS aparelhos transmitem em multicast/broadcast, o unico trafego de
terceiros que um PC comum recebe numa rede comutada:

  - SSDP (239.255.255.250:1900): anuncios UPnP (NOTIFY / respostas M-SEARCH).
    O header LOCATION aponta um XML com friendlyName / modelName / manufacturer.
  - LLMNR (224.0.0.252:5355): respostas de resolucao de nome -> hostname do
    proprio respondente.

NAO ve o conteudo unicast (HTTPS, etc.) dos outros -- isso exige SPAN (switch)
ou captura de pacotes com Npcap. Aqui e 100% passivo e nao interfere na rede.

No Windows as portas 1900/5355 sao usadas por servicos do sistema; usamos
SO_REUSEADDR para dividir o recebimento. Se ainda assim o bind falhar, o
ouvinte daquele protocolo e desativado com um aviso (degradacao graciosa).
"""

from __future__ import annotations

import asyncio
import logging
import re
import socket
import struct
import urllib.request
from typing import Optional

log = logging.getLogger("sentinela.passive")

SSDP_GROUP, SSDP_PORT = "239.255.255.250", 1900
LLMNR_GROUP, LLMNR_PORT = "224.0.0.252", 5355

_UPNP_TAGS = ("friendlyName", "modelName", "manufacturer")
_upnp_cache: dict[str, dict] = {}


def _make_mcast_socket(group: str, port: int) -> socket.socket:
    """Cria um socket UDP inscrito no grupo multicast (compartilhavel)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:  # nao existe no Windows; ignorado quando ausente
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    except (AttributeError, OSError):
        pass
    s.bind(("", port))
    mreq = struct.pack("=4sl", socket.inet_aton(group), socket.INADDR_ANY)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    s.setblocking(False)
    return s


def _fetch_upnp_desc(location: str) -> dict:
    """Baixa o XML de descricao UPnP e extrai friendlyName/modelName/etc."""
    if location in _upnp_cache:
        return _upnp_cache[location]
    info: dict = {}
    try:
        with urllib.request.urlopen(location, timeout=2) as resp:
            xml = resp.read(65536).decode("utf-8", "ignore")
        for tag in _UPNP_TAGS:
            m = re.search(rf"<{tag}>(.*?)</{tag}>", xml, re.IGNORECASE | re.DOTALL)
            if m:
                info[tag] = m.group(1).strip()
    except Exception as exc:
        log.debug("descricao UPnP falhou (%s): %s", location, exc)
    _upnp_cache[location] = info
    return info


def _parse_dns_first_name(data: bytes) -> Optional[str]:
    """Extrai o primeiro QNAME de um pacote DNS/LLMNR (formato wire)."""
    try:
        i, labels = 12, []
        while i < len(data):
            ln = data[i]
            i += 1
            if ln == 0:
                break
            if ln & 0xC0:  # ponteiro de compressao -> para
                break
            labels.append(data[i:i + ln].decode("ascii", "ignore"))
            i += ln
        nome = ".".join(p for p in labels if p)
        return nome or None
    except Exception:
        return None


async def run_forever(storage, settings) -> None:
    """Sobe os ouvintes passivos e enriquece o inventario continuamente."""
    loop = asyncio.get_running_loop()
    from sentinela.sensors.pc_local.discovery import read_arp_table

    arp: dict[str, str] = {}
    nomeados: set[str] = set()  # MACs que ja receberam um nome (evita repetir)
    transports: list = []

    async def refresh_arp() -> None:
        while True:
            try:
                arp.clear()
                arp.update(await read_arp_table())
            except Exception:
                pass
            await asyncio.sleep(30)

    async def enrich(ip: str, hostname: Optional[str], servico: str) -> None:
        mac = arp.get(ip)
        if not mac:  # sem MAC nao da pra ancorar no dispositivo
            return
        device_id, _ = await storage.upsert_device(mac=mac, ip4=ip, hostname=hostname)
        if hostname and mac not in nomeados:
            nomeados.add(mac)
            await storage.add_event(
                device_id=device_id,
                severity="info",
                type="passive.name",
                title=f"Nome descoberto (passivo): {hostname}",
                detail=f"{ip} anunciou via {servico}",
            )

    async def handle_ssdp(data: bytes, ip: str) -> None:
        texto = data.decode("utf-8", "ignore")
        headers = {}
        for linha in texto.split("\r\n")[1:]:
            if ":" in linha:
                k, v = linha.split(":", 1)
                headers[k.strip().upper()] = v.strip()
        nome = None
        location = headers.get("LOCATION")
        if location:
            info = await loop.run_in_executor(None, _fetch_upnp_desc, location)
            nome = info.get("friendlyName") or info.get("modelName")
        await enrich(ip, nome, headers.get("SERVER", "SSDP") or "SSDP")

    async def handle_llmnr(data: bytes, ip: str) -> None:
        if len(data) < 12:
            return
        eh_resposta = bool(data[2] & 0x80)  # bit QR
        # So a RESPOSTA (unicast, rara aqui) traz o nome do proprio respondente;
        # a QUERY (multicast, comum) serve apenas como sinal de presenca.
        nome = _parse_dns_first_name(data) if eh_resposta else None
        await enrich(ip, nome, "LLMNR")

    def _proto_factory(handler):
        class _P(asyncio.DatagramProtocol):
            def datagram_received(self, data, addr):  # noqa: ANN001
                asyncio.ensure_future(handler(data, addr[0]))
        return _P

    for grupo, porta, handler in (
        (SSDP_GROUP, SSDP_PORT, handle_ssdp),
        (LLMNR_GROUP, LLMNR_PORT, handle_llmnr),
    ):
        try:
            sock = _make_mcast_socket(grupo, porta)
            transport, _ = await loop.create_datagram_endpoint(
                _proto_factory(handler), sock=sock
            )
            transports.append(transport)
            log.info("ouvinte passivo ativo em %s:%d", grupo, porta)
        except Exception as exc:
            log.warning(
                "nao consegui ouvir %s:%d (%s) -- porta pode estar ocupada pelo SO",
                grupo, porta, exc,
            )

    if not transports:
        log.warning("nenhum ouvinte passivo ativo; encerrando a task.")
        return

    arp_task = asyncio.ensure_future(refresh_arp())
    try:
        await asyncio.Event().wait()  # roda ate ser cancelada
    except asyncio.CancelledError:
        log.info("ouvinte passivo cancelado")
        raise
    finally:
        arp_task.cancel()
        for t in transports:
            t.close()
