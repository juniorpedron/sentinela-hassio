"""Snoop de vizinhanca L2/L3 (ARP + ICMPv6 ND) para o modo Pi.

Escuta a CAPTURE_IFACE com scapy e observa:
  - ARP (IPv4): request/reply -> mapa ip4 <-> mac
  - ICMPv6 Neighbor Discovery: NS/NA/RA -> mapa ip6 <-> mac

Para cada observacao grava storage.record_ndp e faz upsert_device
(casando por mac), permitindo que o eve_ingest resolva ip -> device.

Uso: python -m sentinela.sensors.pi_span.ndp_snoop

Requer scapy e privilegio para sniff em modo promiscuo. Roda numa thread
dedicada (scapy sniff e bloqueante) e envia os registros ao loop async.
"""
from __future__ import annotations

import asyncio
import logging
import threading
from datetime import datetime, timezone
from typing import Optional

from sentinela.config import Settings, get_settings
from sentinela.common.storage import PgStorage, Storage

logger = logging.getLogger("sentinela.ndp_snoop")

# scapy e opcional; sem ele o snoop nao roda mas o resto do sistema segue.
try:
    from scapy.all import sniff, ARP, Ether  # type: ignore
    from scapy.layers.inet6 import (  # type: ignore
        ICMPv6ND_NS,
        ICMPv6ND_NA,
        ICMPv6ND_RS,
        ICMPv6ND_RA,
        ICMPv6NDOptSrcLLAddr,
        ICMPv6NDOptDstLLAddr,
        IPv6,
    )
    SCAPY_OK = True
except Exception:  # pragma: no cover - ambiente sem scapy/Npcap
    SCAPY_OK = False


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _norm_mac(mac: Optional[str]) -> Optional[str]:
    """Normaliza mac para minusculo com dois-pontos; ignora enderecos nulos."""
    if not mac:
        return None
    mac = mac.lower().strip()
    if mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
        return None
    return mac


class NdpSnooper:
    """Sniff de ARP/ND e gravacao assincrona no storage."""

    def __init__(self, storage: Storage, settings: Settings):
        self.storage = storage
        self.settings = settings
        self.iface = settings.capture_iface
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._stop = threading.Event()
        # Cache ip->mac para evitar upsert/gravacao repetida do mesmo par.
        self._seen: dict[tuple[str, str], float] = {}

    # ---- caminho async: persistencia ---------------------------------------

    async def _persist(self, *, mac: str, ip: str, kind: str) -> None:
        """Grava ndp e faz upsert_device (casa por mac)."""
        await self.storage.record_ndp(ts=_now_iso(), mac=mac, ip=ip, kind=kind)
        is_v4 = ":" not in ip
        await self.storage.upsert_device(
            mac=mac,
            ip4=ip if is_v4 else None,
            ip6=ip if not is_v4 else None,
        )

    def _submit(self, *, mac: Optional[str], ip: Optional[str], kind: str) -> None:
        """Agenda a persistencia no loop async a partir da thread do sniff."""
        mac = _norm_mac(mac)
        if not mac or not ip:
            return
        key = (mac, ip)
        # Deduplica pares vistos ha pouco (janela simples de 30s).
        import time

        now = time.monotonic()
        last = self._seen.get(key)
        if last and (now - last) < 30:
            return
        self._seen[key] = now

        if self._loop is None:
            return
        fut = asyncio.run_coroutine_threadsafe(
            self._persist(mac=mac, ip=ip, kind=kind), self._loop
        )

        def _log_err(f):
            exc = f.exception()
            if exc:  # pragma: no cover
                logger.debug("Falha ao persistir ndp %s/%s: %s", ip, mac, exc)

        fut.add_done_callback(_log_err)

    # ---- caminho scapy: parsing dos pacotes --------------------------------

    def _handle_packet(self, pkt) -> None:
        """Callback do sniff: extrai mac/ip de ARP e ICMPv6 ND."""
        try:
            # --- ARP (IPv4) ---
            if ARP in pkt:
                arp = pkt[ARP]
                # op 1=who-has(request), 2=is-at(reply)
                self._submit(mac=arp.hwsrc, ip=arp.psrc, kind="arp")
                # No reply, o alvo tambem fica conhecido.
                if arp.op == 2:
                    self._submit(mac=arp.hwdst, ip=arp.pdst, kind="arp")
                return

            # --- ICMPv6 Neighbor Discovery (IPv6) ---
            if IPv6 in pkt:
                l2src = pkt[Ether].src if Ether in pkt else None
                ip6src = pkt[IPv6].src

                if ICMPv6ND_NA in pkt:
                    # Neighbor Advertisement: tgt = endereco anunciado.
                    tgt = pkt[ICMPv6ND_NA].tgt
                    lladdr = None
                    if ICMPv6NDOptDstLLAddr in pkt:
                        lladdr = pkt[ICMPv6NDOptDstLLAddr].lladdr
                    self._submit(mac=lladdr or l2src, ip=tgt, kind="na")
                    return

                if ICMPv6ND_NS in pkt:
                    # Neighbor Solicitation: fonte se identifica via SrcLLAddr.
                    lladdr = None
                    if ICMPv6NDOptSrcLLAddr in pkt:
                        lladdr = pkt[ICMPv6NDOptSrcLLAddr].lladdr
                    self._submit(mac=lladdr or l2src, ip=ip6src, kind="ns")
                    return

                if ICMPv6ND_RA in pkt:
                    # Router Advertisement: identifica o roteador (gateway v6).
                    lladdr = None
                    if ICMPv6NDOptSrcLLAddr in pkt:
                        lladdr = pkt[ICMPv6NDOptSrcLLAddr].lladdr
                    self._submit(mac=lladdr or l2src, ip=ip6src, kind="ra")
                    return

                # TODO(sentinela): tratar ICMPv6ND_RS (router solicitation) se util.
        except Exception as exc:  # pragma: no cover
            logger.debug("Erro ao processar pacote ND/ARP: %s", exc)

    def _sniff_blocking(self) -> None:
        """Executa o sniff bloqueante (roda em thread separada)."""
        # Filtro BPF: ARP + ICMPv6 (ND usa ICMPv6).
        bpf = "arp or icmp6"
        logger.info("Sniff ND/ARP iniciado em iface=%s filtro='%s'", self.iface, bpf)
        try:
            sniff(
                iface=self.iface,
                filter=bpf,
                prn=self._handle_packet,
                store=False,
                stop_filter=lambda _p: self._stop.is_set(),
            )
        except Exception as exc:  # pragma: no cover
            logger.error("sniff falhou (privilegio/iface?): %s", exc)

    # ---- ciclo de vida ------------------------------------------------------

    async def run_forever(self) -> None:
        """Inicia a thread de sniff e mantem o loop vivo ate cancelar."""
        if not SCAPY_OK:
            logger.warning(
                "scapy indisponivel; ndp_snoop desativado. "
                "Instale scapy no container de captura."
            )
            # TODO(sentinela): sem scapy, poderiamos cair para leitura de /proc/net/arp.
            return

        self._loop = asyncio.get_running_loop()
        thread = threading.Thread(target=self._sniff_blocking, name="ndp-sniff", daemon=True)
        thread.start()
        try:
            # Mantem a coroutine viva enquanto a thread trabalha.
            while thread.is_alive():
                await asyncio.sleep(1.0)
        finally:
            self._stop.set()


async def _amain() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    settings = get_settings()
    if not settings.db_url:
        raise SystemExit("DB_URL nao configurado; modo Pi exige Postgres/TimescaleDB.")
    storage = PgStorage(settings.db_url)
    await storage.connect()
    snooper = NdpSnooper(storage, settings)
    try:
        await snooper.run_forever()
    finally:
        await storage.close()


def main() -> None:
    """Entrypoint sincrono."""
    try:
        asyncio.run(_amain())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
