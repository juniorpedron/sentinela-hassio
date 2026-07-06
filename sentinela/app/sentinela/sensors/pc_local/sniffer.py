"""Sniffer L2 de pacotes (MODO PC) via scapy + Npcap.

Captura, na interface ativa, os pacotes que dao mais sinal com o MENOR volume,
usando um filtro BPF enxuto:

  - ARP        -> mapa IP<->MAC continuo de todos os aparelhos (broadcast).
  - DHCP       -> quando um aparelho ENTRA na rede: hostname + fingerprint de
                  fabricante (broadcast). Forte sinal de identidade dos OUTROS.
  - DNS        -> consultas DNS REAIS do proprio PC (em tempo real, melhor que
                  o cache do Windows).
  - TLS SNI    -> nome do servidor no ClientHello (HTTPS) do proprio PC -- o
                  dado que a captura por conexao (psutil) nao conseguia obter.

Numa rede WiFi comutada, o adaptador so entrega broadcast/multicast dos OUTROS
(o AP isola o unicast por cliente); por isso DHCP/ARP pegam todos, mas DNS/SNI
sao do proprio PC. Para ver unicast de todos, use SPAN (switch) ou monitor mode.

Requer scapy + Npcap. Desligue com SENTINELA_SNIFFER=0. Se a captura exigir
elevacao (opcao "restrict to Administrators" do Npcap), rode o app como admin.
"""

from __future__ import annotations

import asyncio
import logging
import os
from typing import Optional

log = logging.getLogger("sentinela.sniffer")

# Filtro BPF: ARP, DHCP (67/68), DNS (53) e o 1o byte do payload TCP/443 == 0x16
# (registro TLS handshake, que inclui o ClientHello) -- mantem o volume baixo.
_BPF = (
    "arp or (udp and (port 53 or port 67 or port 68)) "
    "or (tcp port 443 and tcp[((tcp[12]&0xf0)>>2)]=22)"
)


def _fmt_mac(raw) -> Optional[str]:
    try:
        if isinstance(raw, bytes):
            raw = raw[:6]
            return ":".join("%02x" % b for b in raw)
        return str(raw).lower()
    except Exception:
        return None


def parse_sni(data: bytes) -> Optional[str]:
    """Extrai o server_name (SNI) de um ClientHello TLS a partir do payload TCP."""
    try:
        if len(data) < 43 or data[0] != 0x16:  # nao e handshake TLS
            return None
        p = 5  # pula o cabecalho do registro TLS
        if data[p] != 0x01:  # nao e ClientHello
            return None
        p += 4  # tipo(1) + tamanho(3) do handshake
        p += 2 + 32  # versao do cliente + random
        sid_len = data[p]; p += 1 + sid_len          # session id
        cs_len = int.from_bytes(data[p:p + 2], "big"); p += 2 + cs_len  # cipher suites
        comp_len = data[p]; p += 1 + comp_len          # compressao
        ext_total = int.from_bytes(data[p:p + 2], "big"); p += 2
        fim = min(len(data), p + ext_total)
        while p + 4 <= fim:
            etype = int.from_bytes(data[p:p + 2], "big")
            elen = int.from_bytes(data[p + 2:p + 4], "big")
            p += 4
            if etype == 0x0000:  # extensao server_name
                sn = data[p:p + elen]
                if len(sn) >= 5 and sn[2] == 0x00:  # tipo host_name
                    nl = int.from_bytes(sn[3:5], "big")
                    nome = sn[5:5 + nl].decode("ascii", "ignore")
                    return nome or None
                return None
            p += elen
        return None
    except Exception:
        return None


def _pick_iface(local_ip: Optional[str]):
    """Escolhe a interface do scapy cujo IP bate com o do PC."""
    from scapy.all import conf

    for i in conf.ifaces.values():
        if local_ip and getattr(i, "ip", None) == local_ip:
            return i
    return conf.iface


async def run_forever(storage, settings, controls=None) -> None:
    """Sobe o AsyncSniffer e liga/desliga em tempo real via controles."""
    def _importar_scapy():
        from scapy.all import ARP, DHCP, DNS, IP, IPv6, TCP, UDP, AsyncSniffer
        return (ARP, DHCP, DNS, IP, IPv6, TCP, UDP, AsyncSniffer)
    try:
        # Import do scapy FORA do event loop: em algumas maquinas o carregamento
        # do Npcap (load_winpcapy) e lento/travado; assim o dashboard nunca congela.
        _lp = asyncio.get_running_loop()
        ARP, DHCP, DNS, IP, IPv6, TCP, UDP, AsyncSniffer = await asyncio.wait_for(
            _lp.run_in_executor(None, _importar_scapy), timeout=25)
    except Exception as exc:
        log.warning("scapy/Npcap indisponivel ou lento; sniffer L2 desligado (%s)", exc)
        return

    loop = asyncio.get_running_loop()
    from sentinela.sensors.pc_local.own_activity import get_local_identity

    dev_id, local_ip = await get_local_identity(storage)
    iface = _pick_iface(local_ip)

    seen_dns: set = set()
    seen_sni: set = set()
    seen_dhcp: set = set()

    def _schedule(coro) -> None:
        asyncio.run_coroutine_threadsafe(coro, loop)

    def prn(pkt) -> None:
        try:
            # ---- ARP: identidade IP<->MAC de qualquer aparelho ----
            if pkt.haslayer(ARP):
                a = pkt[ARP]
                mac = _fmt_mac(a.hwsrc)
                if mac and a.psrc and a.psrc not in ("0.0.0.0", "") and int(mac.split(":")[0], 16) & 1 == 0:
                    _schedule(storage.record_ndp(mac=mac, ip=a.psrc, kind="arp"))
                    _schedule(storage.upsert_device(mac=mac, ip4=a.psrc))
                return

            # ---- DHCP: aparelho entrando -> hostname + fingerprint ----
            if pkt.haslayer(DHCP):
                mac = _fmt_mac(pkt.src)
                hostname = vendor = None
                fp = None
                for opt in pkt[DHCP].options:
                    if not isinstance(opt, tuple):
                        continue
                    if opt[0] == "hostname":
                        hostname = opt[1].decode("utf-8", "ignore") if isinstance(opt[1], bytes) else str(opt[1])
                    elif opt[0] == "vendor_class_id":
                        vendor = opt[1].decode("utf-8", "ignore") if isinstance(opt[1], bytes) else str(opt[1])
                    elif opt[0] == "param_req_list":
                        fp = ",".join(str(x) for x in opt[1]) if isinstance(opt[1], (list, tuple)) else str(opt[1])
                if mac and mac not in seen_dhcp:
                    seen_dhcp.add(mac)
                    _schedule(storage.upsert_device(mac=mac, hostname=hostname))
                    _schedule(storage.add_event(
                        device_id=None, severity="info", type="dhcp",
                        title=f"DHCP: {hostname or mac} entrou na rede",
                        detail=f"vendor={vendor or '?'} fingerprint={fp or '?'}",
                    ))
                return

            # ---- DNS: consultas reais do proprio PC ----
            if pkt.haslayer(DNS) and pkt[DNS].qr == 0 and pkt[DNS].qd is not None:
                qname = pkt[DNS].qd.qname
                qname = qname.decode("utf-8", "ignore") if isinstance(qname, bytes) else str(qname)
                qname = qname.rstrip(".")
                if qname and (qname, "q") not in seen_dns:
                    seen_dns.add((qname, "q"))
                    if len(seen_dns) > 4000:
                        seen_dns.clear()
                    _schedule(storage.record_dns(
                        device_id=dev_id, client_ip=local_ip, qname=qname,
                        qtype=str(getattr(pkt[DNS].qd, "qtype", "")), answer=None, blocked=False,
                    ))
                return

            # ---- TLS ClientHello: SNI real do proprio PC ----
            if pkt.haslayer(TCP) and pkt.haslayer("Raw"):
                sni = parse_sni(bytes(pkt["Raw"].load))
                if sni:
                    dst = pkt[IP].dst if pkt.haslayer(IP) else (pkt[IPv6].dst if pkt.haslayer(IPv6) else None)
                    key = (sni, dst)
                    if key not in seen_sni:
                        seen_sni.add(key)
                        if len(seen_sni) > 4000:
                            seen_sni.clear()
                        _schedule(storage.record_flow(
                            device_id=dev_id, src_ip=local_ip, dst_ip=dst, dst_port=443,
                            proto="tcp", sni=sni, app_proto="https",
                        ))
        except Exception:
            pass  # um pacote malformado nunca derruba o sniffer

    sniffer = None
    log.info(
        "sniffer L2 pronto em '%s' (ligue/desligue pelo painel)",
        getattr(iface, "description", iface),
    )
    try:
        while True:
            quer = True if controls is None else bool(getattr(controls, "sniffer_enabled", True))
            if quer and sniffer is None:
                try:
                    sniffer = AsyncSniffer(iface=iface, filter=_BPF, prn=prn, store=False)
                    sniffer.start()
                    log.info("sniffer L2 LIGADO -> DHCP/ARP/DNS/SNI reais")
                except Exception as exc:
                    log.warning(
                        "nao consegui iniciar a captura (%s). Se marcou 'restrict to "
                        "Administrators' no Npcap, rode como admin.", exc,
                    )
                    sniffer = None
                    if controls is not None:
                        controls.sniffer_enabled = False
                    await asyncio.sleep(2)
            elif not quer and sniffer is not None:
                try:
                    sniffer.stop()
                except Exception:
                    pass
                sniffer = None
                log.info("sniffer L2 DESLIGADO pelo painel")
            await asyncio.sleep(1)
    except asyncio.CancelledError:
        log.info("sniffer cancelado")
        raise
    finally:
        if sniffer is not None:
            try:
                sniffer.stop()
            except Exception:
                pass
