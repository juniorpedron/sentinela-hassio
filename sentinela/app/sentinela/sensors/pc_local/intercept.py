"""Interceptacao ao vivo por dispositivo (ARP MITM) integrada ao painel.

Ao pedir a interceptacao de um dispositivo, o Sentinela envenena o ARP dele
(e do gateway), liga o encaminhamento IP e captura o DNS/SNI DELE, atribuindo
ao device_id certo. Assim o mapa e o detalhe passam a mostrar o que aquele
aparelho acessa -- coisa que no WiFi nao daria sem MITM.

TRAVAS DE SEGURANCA:
  - so na SUA rede (uso pessoal); intercepta trafego de terceiros (LGPD).
  - AUTO-DESLIGA apos `dur` segundos (padrao 180) e RESTAURA o ARP.
  - restaura o ARP e desliga o forwarding no stop / no encerramento.

Requer scapy + Npcap.
"""

from __future__ import annotations

import asyncio
import logging
import subprocess
import threading
import time

log = logging.getLogger("sentinela.intercept")


class InterceptManager:
    """Gerencia interceptacoes ARP ativas, uma por dispositivo."""

    def __init__(self, storage, settings) -> None:
        self.storage = storage
        self.settings = settings
        self.loop: asyncio.AbstractEventLoop | None = None
        self.active: dict[str, dict] = {}   # device_id -> estado
        self._iface = None
        self._our_mac = None
        self._gw_ip = None
        self._gw_mac = None
        self._fwd = False

    # -- rede -------------------------------------------------------------
    def _ensure_net(self) -> bool:
        if self._iface is not None:
            return self._gw_mac is not None
        try:
            from scapy.all import conf, get_if_hwaddr, getmacbyip

            from sentinela.sensors.pc_local.own_activity import _primary_ipv4
            ip = _primary_ipv4()
            iface = None
            for i in conf.ifaces.values():
                if getattr(i, "ip", None) == ip:
                    iface = i
                    break
            self._iface = iface or conf.iface
            conf.iface = self._iface
            self._our_mac = get_if_hwaddr(self._iface)
            self._gw_ip = conf.route.route("0.0.0.0")[2]
            self._gw_mac = getmacbyip(self._gw_ip)
        except Exception as exc:
            log.warning("rede/scapy indisponivel para interceptacao: %s", exc)
            return False
        return self._gw_mac is not None

    def _forward(self, on: bool) -> None:
        try:
            subprocess.run(
                ["netsh", "interface", "ipv4", "set", "global",
                 f"forwarding={'enabled' if on else 'disabled'}"],
                capture_output=True, timeout=5,
            )
        except Exception:
            pass

    # -- API pro resto do app --------------------------------------------
    def status(self) -> dict:
        agora = time.monotonic()
        return {
            "ativos": [
                {"device_id": did, "ip": st["ip"],
                 "restante_s": max(0, int(st["fim"] - agora))}
                for did, st in self.active.items()
            ]
        }

    async def start(self, device_id: str, dur: int = 180) -> dict:
        if device_id in self.active:
            return {"ok": True, "ja_ativo": True}
        dev = await self.storage.get_device(device_id)
        if not dev or not dev.get("ip4"):
            return {"ok": False, "erro": "dispositivo sem IPv4 conhecido"}
        ip = dev["ip4"]
        if not self._ensure_net():
            return {"ok": False, "erro": "scapy/Npcap indisponivel ou gateway nao resolvido"}

        from scapy.all import ARP, AsyncSniffer, Ether, getmacbyip, srp

        mac = dev.get("mac") or getmacbyip(ip)
        if not mac:
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), timeout=2, retry=1, verbose=0)
            for _s, r in ans:
                mac = r.hwsrc
        if not mac:
            return {"ok": False, "erro": "nao resolvi o MAC do alvo (aparelho offline?)"}
        mac = mac.lower()

        if not self._fwd:
            self._forward(True)
            self._fwd = True

        parar = threading.Event()
        gw_ip, gw_mac, our_mac, iface = self._gw_ip, self._gw_mac, self._our_mac, self._iface

        def envenenar():
            while not parar.is_set():
                from scapy.all import ARP, send
                send(ARP(op=2, pdst=ip, hwdst=mac, psrc=gw_ip, hwsrc=our_mac), verbose=0)
                send(ARP(op=2, pdst=gw_ip, hwdst=gw_mac, psrc=ip, hwsrc=our_mac), verbose=0)
                parar.wait(1.5)

        prn = self._make_prn(device_id, ip)
        bpf = f"ether src {mac} and (udp port 53 or tcp port 443)"
        sniffer = AsyncSniffer(iface=iface, filter=bpf, prn=prn, store=False)
        sniffer.start()
        th = threading.Thread(target=envenenar, daemon=True)
        th.start()

        fim = time.monotonic() + dur
        timer = self.loop.call_later(dur, lambda: asyncio.ensure_future(self.stop(device_id)))
        self.active[device_id] = {
            "ip": ip, "mac": mac, "parar": parar, "sniffer": sniffer,
            "thread": th, "timer": timer, "fim": fim,
        }
        await self.storage.add_event(
            device_id=device_id, severity="warning", type="intercept.start",
            title=f"Interceptacao ARP iniciada: {ip}",
            detail=f"capturando DNS/SNI do dispositivo por {dur}s",
        )
        log.info("interceptacao iniciada para %s (%s)", device_id, ip)
        return {"ok": True, "ip": ip, "dur": dur}

    async def stop(self, device_id: str) -> dict:
        st = self.active.pop(device_id, None)
        if not st:
            return {"ok": True, "ja_parado": True}
        st["parar"].set()
        try:
            st["timer"].cancel()
        except Exception:
            pass
        try:
            st["sniffer"].stop()
        except Exception:
            pass
        # restaura o ARP do alvo e do gateway
        try:
            from scapy.all import ARP, send
            ip, mac = st["ip"], st["mac"]
            for _ in range(5):
                send(ARP(op=2, pdst=ip, hwdst=mac, psrc=self._gw_ip, hwsrc=self._gw_mac), verbose=0)
                send(ARP(op=2, pdst=self._gw_ip, hwdst=self._gw_mac, psrc=ip, hwsrc=mac), verbose=0)
                time.sleep(0.15)
        except Exception:
            pass
        if not self.active and self._fwd:
            self._forward(False)
            self._fwd = False
        await self.storage.add_event(
            device_id=device_id, severity="info", type="intercept.stop",
            title="Interceptacao ARP encerrada", detail=st["ip"],
        )
        log.info("interceptacao encerrada para %s", device_id)
        return {"ok": True}

    async def stop_all(self) -> None:
        for did in list(self.active.keys()):
            await self.stop(did)

    # -- captura ----------------------------------------------------------
    def _make_prn(self, device_id: str, client_ip: str):
        from sentinela.sensors.pc_local.sniffer import parse_sni

        def prn(pkt):
            try:
                from scapy.all import DNS, IP, IPv6, TCP
                if pkt.haslayer(DNS) and pkt[DNS].qr == 0 and pkt[DNS].qd is not None:
                    q = pkt[DNS].qd.qname
                    q = (q.decode("utf-8", "ignore") if isinstance(q, bytes) else str(q)).rstrip(".")
                    if q:
                        asyncio.run_coroutine_threadsafe(
                            self.storage.record_dns(device_id=device_id, client_ip=client_ip,
                                                     qname=q, qtype="A", answer=None, blocked=False),
                            self.loop,
                        )
                elif pkt.haslayer(TCP) and pkt.haslayer("Raw"):
                    sni = parse_sni(bytes(pkt["Raw"].load))
                    if sni:
                        dst = pkt[IP].dst if pkt.haslayer(IP) else (pkt[IPv6].dst if pkt.haslayer(IPv6) else None)
                        asyncio.run_coroutine_threadsafe(
                            self.storage.record_flow(device_id=device_id, src_ip=client_ip, dst_ip=dst,
                                                     dst_port=443, proto="tcp", sni=sni, app_proto="https"),
                            self.loop,
                        )
            except Exception:
                pass

        return prn
