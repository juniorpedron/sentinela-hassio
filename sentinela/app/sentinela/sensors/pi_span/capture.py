"""Captura via SPAN (modo Pi) -- le o espelho e atribui a CADA dispositivo.

A porta espelhada do switch carrega o trafego entre o modem (gateway) e a
rede. Para cada pacote de saida (dispositivo -> internet), o Ethernet de
origem e o MAC do dispositivo e o IP de origem e o IP privado dele. Assim
sabemos QUEM acessou o que -- DNS e SNI reais, por dispositivo.

Requer scapy + a interface de captura em modo promiscuo (o run.sh do add-on
configura). O import do scapy roda FORA do event loop (o carregamento do
libpcap pode ser lento) para nao congelar o dashboard.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
from typing import Optional

log = logging.getLogger("sentinela.pi_capture")

# Filtro BPF enxuto: so o que vira metadado util (DNS + handshakes TLS/HTTP).
_BPF = "udp port 53 or tcp port 443 or tcp port 80"


def _fmt_mac(m: Optional[str]) -> Optional[str]:
    if not m:
        return None
    m = m.lower()
    # ignora MACs de grupo/multicast (bit menos significativo do 1o octeto)
    try:
        if int(m.split(":")[0], 16) & 0x01:
            return None
    except ValueError:
        return None
    return m


async def run_forever(storage, settings, controls=None) -> None:
    """Sobe o sniffer no espelho e alimenta o storage por dispositivo."""
    def _importar_scapy():
        from scapy.all import ARP, DNS, Ether, IP, IPv6, TCP, AsyncSniffer
        return (ARP, DNS, Ether, IP, IPv6, TCP, AsyncSniffer)

    try:
        loop = asyncio.get_running_loop()
        ARP, DNS, Ether, IP, IPv6, TCP, AsyncSniffer = await asyncio.wait_for(
            loop.run_in_executor(None, _importar_scapy), timeout=30
        )
    except Exception as exc:
        log.warning("scapy/libpcap indisponivel; captura SPAN desligada (%s)", exc)
        return

    from sentinela.sensors.pc_local.sniffer import parse_sni  # reusa o parser de SNI

    iface = settings.capture_iface or "eth1"
    try:
        net = ipaddress.ip_network(settings.lan_cidr, strict=False)
    except ValueError:
        net = ipaddress.ip_network("192.168.0.0/24")
    exclude = set(settings.exclude_macs or ())

    def _is_lan(ip: str) -> bool:
        try:
            return ipaddress.ip_address(ip) in net
        except ValueError:
            return False

    def _lan_endpoint(pkt):
        """Devolve (mac, ip) do dispositivo da LAN no pacote, ou (None, None)."""
        if not pkt.haslayer(IP):
            return None, None
        e = pkt.getlayer(Ether)
        if e is None:
            return None, None
        s_ip, d_ip = pkt[IP].src, pkt[IP].dst
        if _is_lan(s_ip):          # saida: origem e o dispositivo
            return _fmt_mac(e.src), s_ip
        if _is_lan(d_ip):          # entrada: destino e o dispositivo
            return _fmt_mac(e.dst), d_ip
        return None, None

    dev_cache: dict[str, str] = {}   # mac -> device_id (evita upsert por pacote)
    seen_dns: set = set()
    seen_sni: set = set()

    def _schedule(coro) -> None:
        asyncio.run_coroutine_threadsafe(coro, loop)

    async def _dev_id(mac: str, ip: str) -> str:
        did = dev_cache.get(mac)
        if did is None:
            did, _new = await storage.upsert_device(mac=mac, ip4=ip)
            dev_cache[mac] = did
        return did

    def prn(pkt) -> None:
        try:
            mac, ip = _lan_endpoint(pkt)
            if not mac or not ip:
                return
            if mac in exclude:          # sensor/IoT excluido da captura profunda
                return

            # ---- DNS: quem consultou qual dominio ----
            if pkt.haslayer(DNS) and pkt[DNS].qr == 0 and pkt[DNS].qd is not None:
                q = pkt[DNS].qd.qname
                q = (q.decode("utf-8", "ignore") if isinstance(q, bytes) else str(q)).rstrip(".")
                key = (mac, q)
                if q and key not in seen_dns:
                    seen_dns.add(key)
                    if len(seen_dns) > 30000:
                        seen_dns.clear()

                    async def _rec(mac=mac, ip=ip, q=q):
                        did = await _dev_id(mac, ip)
                        await storage.record_dns(
                            device_id=did, client_ip=ip, qname=q, qtype="A", blocked=False
                        )
                    _schedule(_rec())
                return

            # ---- TLS ClientHello: SNI real por dispositivo ----
            if pkt.haslayer(TCP) and pkt.haslayer("Raw"):
                sni = parse_sni(bytes(pkt["Raw"].load))
                if sni:
                    dst = pkt[IP].dst if _is_lan(pkt[IP].src) else pkt[IP].src
                    key = (mac, sni)
                    if key not in seen_sni:
                        seen_sni.add(key)
                        if len(seen_sni) > 30000:
                            seen_sni.clear()

                        async def _rec(mac=mac, ip=ip, sni=sni, dst=dst):
                            did = await _dev_id(mac, ip)
                            await storage.record_flow(
                                device_id=did, src_ip=ip, dst_ip=dst, dst_port=443,
                                proto="tcp", sni=sni, app_proto="https",
                            )
                        _schedule(_rec())
        except Exception:
            pass  # um pacote malformado nunca derruba a captura

    try:
        sniffer = AsyncSniffer(iface=iface, filter=_BPF, prn=prn, store=False)
        sniffer.start()
    except Exception as exc:
        log.warning(
            "nao consegui iniciar a captura SPAN em '%s' (%s). Confira o "
            "espelhamento no switch e a interface (CAPTURE_IFACE).", iface, exc,
        )
        return

    log.info(
        "captura SPAN ativa em '%s' (LAN=%s; %d MAC(s) excluido(s) da captura)",
        iface, net, len(exclude),
    )
    try:
        await asyncio.Event().wait()
    except asyncio.CancelledError:
        log.info("captura SPAN cancelada")
        raise
    finally:
        try:
            sniffer.stop()
        except Exception:
            pass
