"""Ingestor do eve.json do Suricata (modo Pi).

Faz tail assincrono do arquivo JSON de eventos gerado pelo Suricata,
mapeia eventos flow/dns/tls para storage.record_flow / storage.record_dns
(extraindo sni e ja4) e resolve o device por ip -> mac usando a tabela ndp
alimentada pelo ndp_snoop.

Uso: python -m sentinela.sensors.pi_span.eve_ingest
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
from typing import Optional

from sentinela.config import Settings, get_settings
from sentinela.common.storage import PgStorage, Storage

logger = logging.getLogger("sentinela.eve_ingest")

# Caminho padrao do eve.json montado no compose (Suricata grava aqui).
DEFAULT_EVE_PATH = os.environ.get("EVE_JSON_PATH", "/var/log/suricata/eve.json")


async def tail_lines(path: str, *, poll: float = 0.5):
    """Gera linhas novas de um arquivo, estilo `tail -F` (assincrono).

    Trata rotacao do arquivo (inode/tamanho reiniciado) e espera o arquivo
    aparecer caso ainda nao exista.
    """
    # Espera o arquivo existir.
    while not os.path.exists(path):
        logger.info("Aguardando eve.json em %s ...", path)
        await asyncio.sleep(poll)

    fh = open(path, "r", encoding="utf-8", errors="replace")
    try:
        # Comeca do fim para nao reprocessar historico ao iniciar.
        fh.seek(0, os.SEEK_END)
        inode = os.fstat(fh.fileno()).st_ino
        while True:
            line = fh.readline()
            if line:
                line = line.strip()
                if line:
                    yield line
                continue

            # Sem dados novos: cede o loop e checa rotacao.
            await asyncio.sleep(poll)
            try:
                st = os.stat(path)
            except FileNotFoundError:
                continue
            # Rotacionou (novo inode) ou truncou (tamanho < posicao atual).
            if st.st_ino != inode or st.st_size < fh.tell():
                logger.info("eve.json rotacionou; reabrindo %s", path)
                fh.close()
                fh = open(path, "r", encoding="utf-8", errors="replace")
                inode = os.fstat(fh.fileno()).st_ino
    finally:
        fh.close()


class EveIngestor:
    """Consome eventos do eve.json e grava no storage."""

    def __init__(self, storage: Storage, settings: Settings, *, eve_path: str = DEFAULT_EVE_PATH):
        self.storage = storage
        self.settings = settings
        self.eve_path = eve_path

    async def _device_id_for_ip(self, ip: Optional[str]) -> Optional[str]:
        """Resolve device_id a partir de um IP via mac descoberto no ndp.

        Consulta a ultima entrada ndp com esse IP para obter o mac e, em
        seguida, garante o device via upsert_device (casa por mac).
        """
        if not ip:
            return None
        mac = await self._mac_for_ip(ip)
        if not mac:
            # TODO(sentinela): fallback opcional resolvendo mac por outra via
            # (ex.: ler tabela ARP local) quando o ndp_snoop ainda nao viu o IP.
            return None
        is_v4 = ":" not in ip
        device_id, _ = await self.storage.upsert_device(
            mac=mac,
            ip4=ip if is_v4 else None,
            ip6=ip if not is_v4 else None,
        )
        return device_id

    async def _mac_for_ip(self, ip: str) -> Optional[str]:
        """Busca o mac mais recente associado ao IP na tabela ndp.

        Usa o conn do PgStorage diretamente (consulta simples de leitura).
        """
        # PgStorage expoe um pool/conn async; usamos uma query direta.
        # TODO(sentinela): mover esta consulta para um metodo dedicado em
        # Storage (ex.: mac_for_ip) para nao depender de detalhe interno.
        get_conn = getattr(self.storage, "_acquire", None)
        if get_conn is None:
            return None
        try:
            async with self.storage._acquire() as conn:  # type: ignore[attr-defined]
                cur = await conn.execute(
                    "SELECT mac FROM ndp WHERE ip = %s ORDER BY ts DESC LIMIT 1",
                    (ip,),
                )
                row = await cur.fetchone()
                if row:
                    return row[0]
        except Exception as exc:  # pragma: no cover - resiliencia de runtime
            logger.debug("Falha ao resolver mac por ip %s: %s", ip, exc)
        return None

    async def handle_flow(self, ev: dict) -> None:
        """Mapeia evento 'flow' -> record_flow."""
        src = ev.get("src_ip")
        dst = ev.get("dest_ip")
        device_id = await self._device_id_for_ip(src) or await self._device_id_for_ip(dst)
        flow = ev.get("flow", {}) or {}
        await self.storage.record_flow(
            ts=ev.get("timestamp"),
            device_id=device_id,
            src_ip=src,
            dst_ip=dst,
            src_port=ev.get("src_port"),
            dst_port=ev.get("dest_port"),
            proto=ev.get("proto"),
            bytes_up=flow.get("bytes_toserver"),
            bytes_down=flow.get("bytes_toclient"),
            sni=None,
            ja4=None,
            app_proto=ev.get("app_proto"),
        )

    async def handle_tls(self, ev: dict) -> None:
        """Mapeia evento 'tls' -> record_flow com sni/ja4 extraidos."""
        src = ev.get("src_ip")
        dst = ev.get("dest_ip")
        device_id = await self._device_id_for_ip(src)
        tls = ev.get("tls", {}) or {}
        sni = tls.get("sni")
        # Suricata pode emitir ja4 em tls.ja4 (Suricata 8) ou aninhado.
        ja4 = tls.get("ja4") or (tls.get("ja4s") if isinstance(tls, dict) else None)
        await self.storage.record_flow(
            ts=ev.get("timestamp"),
            device_id=device_id,
            src_ip=src,
            dst_ip=dst,
            src_port=ev.get("src_port"),
            dst_port=ev.get("dest_port"),
            proto=ev.get("proto"),
            bytes_up=None,
            bytes_down=None,
            sni=sni,
            ja4=ja4,
            app_proto="tls",
        )

    async def handle_dns(self, ev: dict) -> None:
        """Mapeia evento 'dns' (respostas/consultas) -> record_dns."""
        dns = ev.get("dns", {}) or {}
        # So gravamos consultas (query) e respostas com answer resolvido.
        qtype = dns.get("rrtype") or dns.get("qtype")
        qname = dns.get("rrname") or dns.get("query", [{}])[0].get("rrname") if dns else None
        client_ip = ev.get("src_ip")
        device_id = await self._device_id_for_ip(client_ip)

        answer = None
        # Suricata v2 dns: respostas ficam em dns.answers[].rdata
        answers = dns.get("answers")
        if isinstance(answers, list) and answers:
            rdatas = [a.get("rdata") for a in answers if a.get("rdata")]
            if rdatas:
                answer = ",".join(rdatas)

        await self.storage.record_dns(
            ts=ev.get("timestamp"),
            device_id=device_id,
            client_ip=client_ip,
            qname=qname,
            qtype=qtype,
            answer=answer,
            blocked=False,  # bloqueio e resolvido pelo Technitium; TODO(sentinela): correlacionar
        )

    async def dispatch(self, ev: dict) -> None:
        """Roteia um evento pelo campo event_type."""
        etype = ev.get("event_type")
        try:
            if etype == "flow":
                await self.handle_flow(ev)
            elif etype == "tls":
                await self.handle_tls(ev)
            elif etype == "dns":
                await self.handle_dns(ev)
            # TODO(sentinela): tratar 'alert' -> add_event(severity) e 'http'/'fileinfo'.
        except Exception as exc:  # pragma: no cover
            logger.exception("Erro ao processar evento %s: %s", etype, exc)

    async def run_forever(self) -> None:
        """Loop principal: tail do eve.json + dispatch de cada linha JSON."""
        logger.info("Ingestor iniciado; lendo %s", self.eve_path)
        async for line in tail_lines(self.eve_path):
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            await self.dispatch(ev)


async def _amain() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    settings = get_settings()
    if not settings.db_url:
        raise SystemExit("DB_URL nao configurado; modo Pi exige Postgres/TimescaleDB.")
    storage = PgStorage(settings.db_url)
    await storage.connect()
    ingestor = EveIngestor(storage, settings)
    try:
        await ingestor.run_forever()
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
