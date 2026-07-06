"""Camada de armazenamento do Sentinela.

Define a classe base assincrona ``Storage`` (contrato compartilhado) e duas
implementacoes:

- ``PgStorage``  -> Postgres/TimescaleDB (modo Pi), via psycopg 3 async.
- ``SqliteStorage`` -> SQLite (modo PC), via aiosqlite.

Ambas expoem exatamente os mesmos metodos e os mesmos nomes de tabela/coluna,
de modo que a API e o dashboard funcionam identicos nos dois modos.

O sistema de listeners permite ao WebSocket ``/api/live`` receber cada novo
registro (device/dns/flow/event) em tempo real via ``_notify``.
"""
from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Awaitable, Callable, Optional


def _now_iso() -> str:
    """Timestamp atual em ISO8601 UTC (uniforme entre os dois bancos)."""
    return datetime.now(timezone.utc).isoformat()


# Assinatura de um listener: recebe uma msg {"kind": ..., "payload": {...}}.
# Pode ser sincrono ou assincrono (corotina).
Listener = Callable[[dict], Any]


class Storage:
    """Classe base assincrona. Define o contrato e o mecanismo de listeners.

    As subclasses devem implementar ``connect``/``close`` e os metodos de
    persistencia/consulta marcados como ``NotImplementedError``.
    """

    def __init__(self) -> None:
        # Listeners registrados (ex.: conexoes WebSocket ativas).
        self._listeners: list[Listener] = []

    # ------------------------------------------------------------------ #
    # Ciclo de vida
    # ------------------------------------------------------------------ #
    async def connect(self) -> None:  # pragma: no cover - abstrato
        raise NotImplementedError

    async def close(self) -> None:  # pragma: no cover - abstrato
        raise NotImplementedError

    # ------------------------------------------------------------------ #
    # Listeners / notificacao ao vivo
    # ------------------------------------------------------------------ #
    def add_listener(self, cb: Listener) -> None:
        """Registra um callback para novos registros."""
        if cb not in self._listeners:
            self._listeners.append(cb)

    def remove_listener(self, cb: Listener) -> None:
        """Remove um callback previamente registrado (idempotente)."""
        try:
            self._listeners.remove(cb)
        except ValueError:
            pass

    def _notify(self, kind: str, payload: dict) -> None:
        """Dispara ``msg = {"kind": kind, "payload": payload}`` a cada listener.

        Suporta callbacks sincronos e corotinas. Erros em um listener nunca
        derrubam o fluxo de gravacao.
        """
        msg = {"kind": kind, "payload": payload}
        for cb in list(self._listeners):
            try:
                res = cb(msg)
                if asyncio.iscoroutine(res):
                    # Agenda a corotina sem bloquear o gravador.
                    asyncio.ensure_future(res)
            except Exception:
                # TODO(sentinela): logar falha de listener sem interromper.
                pass

    # ------------------------------------------------------------------ #
    # Escrita
    # ------------------------------------------------------------------ #
    async def upsert_device(
        self,
        *,
        mac: str,
        mac_vendor: Optional[str] = None,
        hostname: Optional[str] = None,
        ip4: Optional[str] = None,
        ip6: Optional[str] = None,
    ) -> tuple[str, bool]:  # pragma: no cover - abstrato
        """Insere/atualiza dispositivo casando por MAC. Retorna (device_id, is_new)."""
        raise NotImplementedError

    async def record_flow(self, **kw: Any) -> None:  # pragma: no cover - abstrato
        raise NotImplementedError

    async def record_dns(self, **kw: Any) -> None:  # pragma: no cover - abstrato
        raise NotImplementedError

    async def record_ndp(self, **kw: Any) -> None:  # pragma: no cover - abstrato
        raise NotImplementedError

    async def add_event(
        self,
        *,
        device_id: Optional[str] = None,
        severity: str,
        type: str,
        title: str,
        detail: Optional[str] = None,
    ) -> None:  # pragma: no cover - abstrato
        raise NotImplementedError

    # ------------------------------------------------------------------ #
    # Leitura
    # ------------------------------------------------------------------ #
    async def list_devices(self) -> list[dict]:  # pragma: no cover - abstrato
        raise NotImplementedError

    async def get_device(self, device_id: str) -> Optional[dict]:  # pragma: no cover
        raise NotImplementedError

    async def recent_flows(
        self, device_id: Optional[str] = None, limit: int = 100
    ) -> list[dict]:  # pragma: no cover - abstrato
        raise NotImplementedError

    async def recent_dns(
        self, device_id: Optional[str] = None, limit: int = 100
    ) -> list[dict]:  # pragma: no cover - abstrato
        raise NotImplementedError

    async def list_events(
        self, severity: Optional[str] = None, limit: int = 100
    ) -> list[dict]:  # pragma: no cover - abstrato
        raise NotImplementedError

    async def update_device(
        self,
        device_id: str,
        *,
        label: Optional[str] = None,
        trust_state: Optional[str] = None,
        profile: Optional[str] = None,
    ) -> Optional[dict]:  # pragma: no cover - abstrato
        """Atualiza campos editaveis do dispositivo (usado pelo POST da API)."""
        raise NotImplementedError

    async def stats(self) -> dict:  # pragma: no cover - abstrato
        """Resumo: {devices, unknown_devices, flows_24h, dns_24h, events_24h}."""
        raise NotImplementedError

    async def timeline(self, hours: int = 24) -> list[dict]:  # pragma: no cover
        """Contagem de flows/dns/eventos por hora nas ultimas `hours` horas.

        Retorna lista ordenada [{bucket, flows, dns, events}] para grafico.
        """
        raise NotImplementedError

    async def top(
        self, kind: str = "domains", hours: int = 24, limit: int = 10
    ) -> list[dict]:  # pragma: no cover - abstrato
        """Ranking dos itens mais frequentes na janela.

        kind: 'domains' (qname), 'apps' (app_proto), 'hosts' (sni),
        'talkers' (device). Retorna [{label, total}].
        """
        raise NotImplementedError


# ====================================================================== #
# Implementacao Postgres / TimescaleDB (modo Pi)
# ====================================================================== #
class PgStorage(Storage):
    """Armazenamento em Postgres/TimescaleDB via psycopg 3 async."""

    def __init__(self, dsn: str) -> None:
        super().__init__()
        self._dsn = dsn
        self._pool: Any = None  # AsyncConnectionPool

    async def connect(self) -> None:
        """Abre o pool de conexoes. O schema Pi e criado via migracoes/compose."""
        # Import tardio: psycopg so e dependencia obrigatoria no modo Pi.
        from psycopg_pool import AsyncConnectionPool

        self._pool = AsyncConnectionPool(self._dsn, open=False)
        await self._pool.open()

    async def close(self) -> None:
        if self._pool is not None:
            await self._pool.close()
            self._pool = None

    # -- helpers -------------------------------------------------------- #
    async def _fetchall(self, sql: str, params: tuple = ()) -> list[dict]:
        from psycopg.rows import dict_row

        async with self._pool.connection() as conn:
            async with conn.cursor(row_factory=dict_row) as cur:
                await cur.execute(sql, params)
                return list(await cur.fetchall())

    async def _fetchone(self, sql: str, params: tuple = ()) -> Optional[dict]:
        from psycopg.rows import dict_row

        async with self._pool.connection() as conn:
            async with conn.cursor(row_factory=dict_row) as cur:
                await cur.execute(sql, params)
                return await cur.fetchone()

    # -- escrita -------------------------------------------------------- #
    async def upsert_device(
        self,
        *,
        mac: str,
        mac_vendor: Optional[str] = None,
        hostname: Optional[str] = None,
        ip4: Optional[str] = None,
        ip6: Optional[str] = None,
    ) -> tuple[str, bool]:
        from psycopg.rows import dict_row

        now = _now_iso()
        async with self._pool.connection() as conn:
            async with conn.cursor(row_factory=dict_row) as cur:
                await cur.execute("SELECT * FROM device WHERE mac = %s", (mac,))
                existing = await cur.fetchone()

                if existing is None:
                    # Novo dispositivo: cria com defaults do contrato.
                    device_id = uuid.uuid4().hex
                    await cur.execute(
                        """
                        INSERT INTO device
                            (id, mac, mac_vendor, hostname, ip4, ip6,
                             trust_state, profile, first_seen, last_seen)
                        VALUES (%s, %s, %s, %s, %s, %s,
                                'unknown', 'desconhecido', %s, %s)
                        """,
                        (device_id, mac, mac_vendor, hostname, ip4, ip6, now, now),
                    )
                    await conn.commit()
                    device = await self._fetchone(
                        "SELECT * FROM device WHERE id = %s", (device_id,)
                    )
                    is_new = True
                else:
                    # Existente: atualiza campos nao-nulos e last_seen (COALESCE).
                    device_id = existing["id"]
                    await cur.execute(
                        """
                        UPDATE device SET
                            mac_vendor = COALESCE(%s, mac_vendor),
                            hostname   = COALESCE(%s, hostname),
                            ip4        = COALESCE(%s, ip4),
                            ip6        = COALESCE(%s, ip6),
                            last_seen  = %s
                        WHERE id = %s
                        """,
                        (mac_vendor, hostname, ip4, ip6, now, device_id),
                    )
                    await conn.commit()
                    device = await self._fetchone(
                        "SELECT * FROM device WHERE id = %s", (device_id,)
                    )
                    is_new = False

        if is_new:
            # Evento + notificacao ao vivo de dispositivo novo.
            await self.add_event(
                device_id=device_id,
                severity="info",
                type="device.new",
                title=f"Novo dispositivo detectado: {mac}",
                detail=hostname or ip4 or ip6,
            )
            self._notify("device", device or {"id": device_id, "mac": mac})

        return device_id, is_new

    async def record_flow(self, **kw: Any) -> None:
        payload = {
            "ts": kw.get("ts") or _now_iso(),
            "device_id": kw.get("device_id"),
            "src_ip": kw.get("src_ip"),
            "dst_ip": kw.get("dst_ip"),
            "src_port": kw.get("src_port"),
            "dst_port": kw.get("dst_port"),
            "proto": kw.get("proto"),
            "bytes_up": kw.get("bytes_up", 0),
            "bytes_down": kw.get("bytes_down", 0),
            "sni": kw.get("sni"),
            "ja4": kw.get("ja4"),
            "app_proto": kw.get("app_proto"),
        }
        async with self._pool.connection() as conn:
            await conn.execute(
                """
                INSERT INTO flow
                    (ts, device_id, src_ip, dst_ip, src_port, dst_port, proto,
                     bytes_up, bytes_down, sni, ja4, app_proto)
                VALUES (%(ts)s, %(device_id)s, %(src_ip)s, %(dst_ip)s,
                        %(src_port)s, %(dst_port)s, %(proto)s, %(bytes_up)s,
                        %(bytes_down)s, %(sni)s, %(ja4)s, %(app_proto)s)
                """,
                payload,
            )
            await conn.commit()
        self._notify("flow", payload)

    async def record_dns(self, **kw: Any) -> None:
        payload = {
            "ts": kw.get("ts") or _now_iso(),
            "device_id": kw.get("device_id"),
            "client_ip": kw.get("client_ip"),
            "qname": kw.get("qname"),
            "qtype": kw.get("qtype"),
            "answer": kw.get("answer"),
            "blocked": bool(kw.get("blocked", False)),
        }
        async with self._pool.connection() as conn:
            await conn.execute(
                """
                INSERT INTO dns_query
                    (ts, device_id, client_ip, qname, qtype, answer, blocked)
                VALUES (%(ts)s, %(device_id)s, %(client_ip)s, %(qname)s,
                        %(qtype)s, %(answer)s, %(blocked)s)
                """,
                payload,
            )
            await conn.commit()
        self._notify("dns", payload)

    async def record_ndp(self, **kw: Any) -> None:
        payload = {
            "ts": kw.get("ts") or _now_iso(),
            "mac": kw.get("mac"),
            "ip": kw.get("ip"),
            "kind": kw.get("kind"),
        }
        async with self._pool.connection() as conn:
            await conn.execute(
                "INSERT INTO ndp (ts, mac, ip, kind) "
                "VALUES (%(ts)s, %(mac)s, %(ip)s, %(kind)s)",
                payload,
            )
            await conn.commit()
        # NDP nao vai para o feed ao vivo por padrao (ruidoso).

    async def add_event(
        self,
        *,
        device_id: Optional[str] = None,
        severity: str,
        type: str,
        title: str,
        detail: Optional[str] = None,
    ) -> None:
        payload = {
            "ts": _now_iso(),
            "device_id": device_id,
            "severity": severity,
            "type": type,
            "title": title,
            "detail": detail,
        }
        async with self._pool.connection() as conn:
            await conn.execute(
                """
                INSERT INTO event (ts, device_id, severity, type, title, detail)
                VALUES (%(ts)s, %(device_id)s, %(severity)s, %(type)s,
                        %(title)s, %(detail)s)
                """,
                payload,
            )
            await conn.commit()
        self._notify("event", payload)

    # -- leitura -------------------------------------------------------- #
    async def list_devices(self) -> list[dict]:
        return await self._fetchall("SELECT * FROM device ORDER BY last_seen DESC")

    async def get_device(self, device_id: str) -> Optional[dict]:
        return await self._fetchone("SELECT * FROM device WHERE id = %s", (device_id,))

    async def recent_flows(
        self, device_id: Optional[str] = None, limit: int = 100
    ) -> list[dict]:
        if device_id:
            return await self._fetchall(
                "SELECT * FROM flow WHERE device_id = %s ORDER BY ts DESC LIMIT %s",
                (device_id, limit),
            )
        return await self._fetchall(
            "SELECT * FROM flow ORDER BY ts DESC LIMIT %s", (limit,)
        )

    async def recent_dns(
        self, device_id: Optional[str] = None, limit: int = 100
    ) -> list[dict]:
        if device_id:
            return await self._fetchall(
                "SELECT * FROM dns_query WHERE device_id = %s "
                "ORDER BY ts DESC LIMIT %s",
                (device_id, limit),
            )
        return await self._fetchall(
            "SELECT * FROM dns_query ORDER BY ts DESC LIMIT %s", (limit,)
        )

    async def list_events(
        self, severity: Optional[str] = None, limit: int = 100
    ) -> list[dict]:
        if severity:
            return await self._fetchall(
                "SELECT * FROM event WHERE severity = %s ORDER BY ts DESC LIMIT %s",
                (severity, limit),
            )
        return await self._fetchall(
            "SELECT * FROM event ORDER BY ts DESC LIMIT %s", (limit,)
        )

    async def update_device(
        self,
        device_id: str,
        *,
        label: Optional[str] = None,
        trust_state: Optional[str] = None,
        profile: Optional[str] = None,
    ) -> Optional[dict]:
        # Atualiza apenas os campos fornecidos (COALESCE mantem o valor atual).
        async with self._pool.connection() as conn:
            await conn.execute(
                """
                UPDATE device SET
                    label       = COALESCE(%s, label),
                    trust_state = COALESCE(%s, trust_state),
                    profile     = COALESCE(%s, profile)
                WHERE id = %s
                """,
                (label, trust_state, profile, device_id),
            )
            await conn.commit()
        return await self.get_device(device_id)

    async def stats(self) -> dict:
        row = await self._fetchone(
            """
            SELECT
                (SELECT count(*) FROM device) AS devices,
                (SELECT count(*) FROM device WHERE trust_state = 'unknown')
                    AS unknown_devices,
                (SELECT count(*) FROM flow
                    WHERE ts > now() - interval '24 hours') AS flows_24h,
                (SELECT count(*) FROM dns_query
                    WHERE ts > now() - interval '24 hours') AS dns_24h,
                (SELECT count(*) FROM event
                    WHERE ts > now() - interval '24 hours') AS events_24h
            """
        )
        return row or {
            "devices": 0,
            "unknown_devices": 0,
            "flows_24h": 0,
            "dns_24h": 0,
            "events_24h": 0,
        }
    async def timeline(self, hours: int = 24) -> list[dict]:
        rows = await self._fetchall(
            """
            WITH f AS (SELECT date_trunc('hour', ts) b, count(*) n FROM flow
                       WHERE ts > now() - make_interval(hours => %s) GROUP BY 1),
                 d AS (SELECT date_trunc('hour', ts) b, count(*) n FROM dns_query
                       WHERE ts > now() - make_interval(hours => %s) GROUP BY 1),
                 e AS (SELECT date_trunc('hour', ts) b, count(*) n FROM event
                       WHERE ts > now() - make_interval(hours => %s) GROUP BY 1)
            SELECT to_char(g.b, 'YYYY-MM-DD"T"HH24') AS bucket,
                   coalesce(f.n, 0) AS flows,
                   coalesce(d.n, 0) AS dns,
                   coalesce(e.n, 0) AS events
            FROM (SELECT b FROM f UNION SELECT b FROM d UNION SELECT b FROM e) g
            LEFT JOIN f ON f.b = g.b
            LEFT JOIN d ON d.b = g.b
            LEFT JOIN e ON e.b = g.b
            ORDER BY bucket
            """,
            (hours, hours, hours),
        )
        return rows

    async def top(self, kind: str = "domains", hours: int = 24, limit: int = 10) -> list[dict]:
        if kind == "talkers":
            return await self._fetchall(
                "SELECT coalesce(d.label, d.hostname, d.mac, '?') AS label, "
                "count(*) AS total FROM flow f JOIN device d ON d.id = f.device_id "
                "WHERE f.ts > now() - make_interval(hours => %s) "
                "GROUP BY 1 ORDER BY total DESC LIMIT %s",
                (hours, limit),
            )
        tbl, col = {
            "domains": ("dns_query", "qname"),
            "apps": ("flow", "app_proto"),
            "hosts": ("flow", "sni"),
        }.get(kind, ("dns_query", "qname"))
        return await self._fetchall(
            f"SELECT {col} AS label, count(*) AS total FROM {tbl} "
            f"WHERE ts > now() - make_interval(hours => %s) "
            f"AND {col} IS NOT NULL AND {col} <> '' "
            f"GROUP BY {col} ORDER BY total DESC LIMIT %s",
            (hours, limit),
        )


# ====================================================================== #
# Implementacao SQLite (modo PC)
# ====================================================================== #
# Caminho do schema SQLite relativo a raiz do pacote sentinela.
_SCHEMA_SQLITE = Path(__file__).resolve().parents[2] / "db" / "schema_sqlite.sql"


class SqliteStorage(Storage):
    """Armazenamento em SQLite via aiosqlite (aplica o schema no connect)."""

    def __init__(self, path: str) -> None:
        super().__init__()
        self._path = path
        self._db: Any = None  # aiosqlite.Connection
        self._lock = asyncio.Lock()  # serializa escrita (SQLite single-writer)

    async def connect(self) -> None:
        """Abre a conexao e aplica ``db/schema_sqlite.sql`` (IF NOT EXISTS)."""
        import aiosqlite

        self._db = await aiosqlite.connect(self._path)
        self._db.row_factory = aiosqlite.Row
        # PRAGMAs de robustez e desempenho para uso concorrente leitura/escrita.
        await self._db.execute("PRAGMA journal_mode=WAL")
        await self._db.execute("PRAGMA foreign_keys=ON")
        await self._db.execute("PRAGMA synchronous=NORMAL")
        await self._db.execute("PRAGMA temp_store=MEMORY")
        await self._db.execute("PRAGMA cache_size=-16000")
        await self._db.execute("PRAGMA busy_timeout=5000")
        try:
            schema_sql = _SCHEMA_SQLITE.read_text(encoding="utf-8")
            await self._db.executescript(schema_sql)
        except FileNotFoundError:
            # TODO(sentinela): schema ausente; garantir db/schema_sqlite.sql no deploy.
            pass
        await self._db.commit()

    async def close(self) -> None:
        if self._db is not None:
            await self._db.close()
            self._db = None

    # -- helpers -------------------------------------------------------- #
    async def _fetchall(self, sql: str, params: tuple = ()) -> list[dict]:
        cur = await self._db.execute(sql, params)
        rows = await cur.fetchall()
        await cur.close()
        return [dict(r) for r in rows]

    async def _fetchone(self, sql: str, params: tuple = ()) -> Optional[dict]:
        cur = await self._db.execute(sql, params)
        row = await cur.fetchone()
        await cur.close()
        return dict(row) if row is not None else None

    # -- escrita -------------------------------------------------------- #
    async def upsert_device(
        self,
        *,
        mac: str,
        mac_vendor: Optional[str] = None,
        hostname: Optional[str] = None,
        ip4: Optional[str] = None,
        ip6: Optional[str] = None,
    ) -> tuple[str, bool]:
        now = _now_iso()
        async with self._lock:
            existing = await self._fetchone(
                "SELECT * FROM device WHERE mac = ?", (mac,)
            )
            if existing is None:
                device_id = uuid.uuid4().hex
                await self._db.execute(
                    """
                    INSERT INTO device
                        (id, mac, mac_vendor, hostname, ip4, ip6,
                         trust_state, profile, first_seen, last_seen)
                    VALUES (?, ?, ?, ?, ?, ?, 'unknown', 'desconhecido', ?, ?)
                    """,
                    (device_id, mac, mac_vendor, hostname, ip4, ip6, now, now),
                )
                await self._db.commit()
                is_new = True
            else:
                device_id = existing["id"]
                await self._db.execute(
                    """
                    UPDATE device SET
                        mac_vendor = COALESCE(?, mac_vendor),
                        hostname   = COALESCE(?, hostname),
                        ip4        = COALESCE(?, ip4),
                        ip6        = COALESCE(?, ip6),
                        last_seen  = ?
                    WHERE id = ?
                    """,
                    (mac_vendor, hostname, ip4, ip6, now, device_id),
                )
                await self._db.commit()
                is_new = False

        device = await self.get_device(device_id)
        if is_new:
            await self.add_event(
                device_id=device_id,
                severity="info",
                type="device.new",
                title=f"Novo dispositivo detectado: {mac}",
                detail=hostname or ip4 or ip6,
            )
            self._notify("device", device or {"id": device_id, "mac": mac})

        return device_id, is_new

    async def record_flow(self, **kw: Any) -> None:
        payload = {
            "ts": kw.get("ts") or _now_iso(),
            "device_id": kw.get("device_id"),
            "src_ip": kw.get("src_ip"),
            "dst_ip": kw.get("dst_ip"),
            "src_port": kw.get("src_port"),
            "dst_port": kw.get("dst_port"),
            "proto": kw.get("proto"),
            "bytes_up": kw.get("bytes_up", 0),
            "bytes_down": kw.get("bytes_down", 0),
            "sni": kw.get("sni"),
            "ja4": kw.get("ja4"),
            "app_proto": kw.get("app_proto"),
        }
        async with self._lock:
            await self._db.execute(
                """
                INSERT INTO flow
                    (ts, device_id, src_ip, dst_ip, src_port, dst_port, proto,
                     bytes_up, bytes_down, sni, ja4, app_proto)
                VALUES (:ts, :device_id, :src_ip, :dst_ip, :src_port, :dst_port,
                        :proto, :bytes_up, :bytes_down, :sni, :ja4, :app_proto)
                """,
                payload,
            )
            await self._db.commit()
        self._notify("flow", payload)

    async def record_dns(self, **kw: Any) -> None:
        payload = {
            "ts": kw.get("ts") or _now_iso(),
            "device_id": kw.get("device_id"),
            "client_ip": kw.get("client_ip"),
            "qname": kw.get("qname"),
            "qtype": kw.get("qtype"),
            "answer": kw.get("answer"),
            "blocked": 1 if kw.get("blocked", False) else 0,
        }
        async with self._lock:
            await self._db.execute(
                """
                INSERT INTO dns_query
                    (ts, device_id, client_ip, qname, qtype, answer, blocked)
                VALUES (:ts, :device_id, :client_ip, :qname, :qtype, :answer,
                        :blocked)
                """,
                payload,
            )
            await self._db.commit()
        # Normaliza blocked para bool no feed ao vivo.
        payload["blocked"] = bool(payload["blocked"])
        self._notify("dns", payload)

    async def record_ndp(self, **kw: Any) -> None:
        payload = {
            "ts": kw.get("ts") or _now_iso(),
            "mac": kw.get("mac"),
            "ip": kw.get("ip"),
            "kind": kw.get("kind"),
        }
        async with self._lock:
            await self._db.execute(
                "INSERT INTO ndp (ts, mac, ip, kind) "
                "VALUES (:ts, :mac, :ip, :kind)",
                payload,
            )
            await self._db.commit()
        # NDP nao vai para o feed ao vivo por padrao (ruidoso).

    async def add_event(
        self,
        *,
        device_id: Optional[str] = None,
        severity: str,
        type: str,
        title: str,
        detail: Optional[str] = None,
    ) -> None:
        payload = {
            "ts": _now_iso(),
            "device_id": device_id,
            "severity": severity,
            "type": type,
            "title": title,
            "detail": detail,
        }
        async with self._lock:
            await self._db.execute(
                """
                INSERT INTO event (ts, device_id, severity, type, title, detail)
                VALUES (:ts, :device_id, :severity, :type, :title, :detail)
                """,
                payload,
            )
            await self._db.commit()
        self._notify("event", payload)

    # -- leitura -------------------------------------------------------- #
    async def list_devices(self) -> list[dict]:
        return await self._fetchall("SELECT * FROM device ORDER BY last_seen DESC")

    async def get_device(self, device_id: str) -> Optional[dict]:
        return await self._fetchone("SELECT * FROM device WHERE id = ?", (device_id,))

    async def recent_flows(
        self, device_id: Optional[str] = None, limit: int = 100
    ) -> list[dict]:
        if device_id:
            return await self._fetchall(
                "SELECT * FROM flow WHERE device_id = ? ORDER BY ts DESC LIMIT ?",
                (device_id, limit),
            )
        return await self._fetchall(
            "SELECT * FROM flow ORDER BY ts DESC LIMIT ?", (limit,)
        )

    async def recent_dns(
        self, device_id: Optional[str] = None, limit: int = 100
    ) -> list[dict]:
        if device_id:
            return await self._fetchall(
                "SELECT * FROM dns_query WHERE device_id = ? "
                "ORDER BY ts DESC LIMIT ?",
                (device_id, limit),
            )
        return await self._fetchall(
            "SELECT * FROM dns_query ORDER BY ts DESC LIMIT ?", (limit,)
        )

    async def list_events(
        self, severity: Optional[str] = None, limit: int = 100
    ) -> list[dict]:
        if severity:
            return await self._fetchall(
                "SELECT * FROM event WHERE severity = ? ORDER BY ts DESC LIMIT ?",
                (severity, limit),
            )
        return await self._fetchall(
            "SELECT * FROM event ORDER BY ts DESC LIMIT ?", (limit,)
        )

    async def update_device(
        self,
        device_id: str,
        *,
        label: Optional[str] = None,
        trust_state: Optional[str] = None,
        profile: Optional[str] = None,
    ) -> Optional[dict]:
        async with self._lock:
            await self._db.execute(
                """
                UPDATE device SET
                    label       = COALESCE(?, label),
                    trust_state = COALESCE(?, trust_state),
                    profile     = COALESCE(?, profile)
                WHERE id = ?
                """,
                (label, trust_state, profile, device_id),
            )
            await self._db.commit()
        return await self.get_device(device_id)

    async def stats(self) -> dict:
        # No SQLite os ts sao ISO8601; comparamos com string de 24h atras (UTC).
        from datetime import timedelta

        cutoff = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
        row = await self._fetchone(
            """
            SELECT
                (SELECT count(*) FROM device) AS devices,
                (SELECT count(*) FROM device WHERE trust_state = 'unknown')
                    AS unknown_devices,
                (SELECT count(*) FROM flow WHERE ts > ?) AS flows_24h,
                (SELECT count(*) FROM dns_query WHERE ts > ?) AS dns_24h,
                (SELECT count(*) FROM event WHERE ts > ?) AS events_24h
            """,
            (cutoff, cutoff, cutoff),
        )
        return row or {
            "devices": 0,
            "unknown_devices": 0,
            "flows_24h": 0,
            "dns_24h": 0,
            "events_24h": 0,
        }
    async def timeline(self, hours: int = 24) -> list[dict]:
        from datetime import timedelta

        cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()

        async def por_hora(tbl: str) -> dict:
            rows = await self._fetchall(
                f"SELECT substr(ts, 1, 13) AS bucket, count(*) AS n "
                f"FROM {tbl} WHERE ts > ? GROUP BY bucket",
                (cutoff,),
            )
            return {r["bucket"]: r["n"] for r in rows}

        flows = await por_hora("flow")
        dns = await por_hora("dns_query")
        events = await por_hora("event")
        buckets = sorted(set(flows) | set(dns) | set(events))
        return [
            {
                "bucket": b,
                "flows": flows.get(b, 0),
                "dns": dns.get(b, 0),
                "events": events.get(b, 0),
            }
            for b in buckets
        ]

    async def top(self, kind: str = "domains", hours: int = 24, limit: int = 10) -> list[dict]:
        from datetime import timedelta

        cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
        if kind == "talkers":
            rows = await self._fetchall(
                "SELECT coalesce(d.label, d.hostname, d.mac, '?') AS label, "
                "count(*) AS total FROM flow f JOIN device d ON d.id = f.device_id "
                "WHERE f.ts > ? GROUP BY f.device_id ORDER BY total DESC LIMIT ?",
                (cutoff, limit),
            )
            return [{"label": r["label"], "total": r["total"]} for r in rows]
        tbl, col = {
            "domains": ("dns_query", "qname"),
            "apps": ("flow", "app_proto"),
            "hosts": ("flow", "sni"),
        }.get(kind, ("dns_query", "qname"))
        rows = await self._fetchall(
            f"SELECT {col} AS label, count(*) AS total FROM {tbl} "
            f"WHERE ts > ? AND {col} IS NOT NULL AND {col} <> '' "
            f"GROUP BY {col} ORDER BY total DESC LIMIT ?",
            (cutoff, limit),
        )
        return [{"label": r["label"], "total": r["total"]} for r in rows]


# ====================================================================== #
# Factory
# ====================================================================== #
def get_storage(settings: Any) -> Storage:
    """Escolhe a implementacao de storage conforme ``settings.mode``.

    - mode == "pi" -> PgStorage(settings.db_url)
    - qualquer outro (default "pc") -> SqliteStorage(settings.db_path)
    """
    mode = getattr(settings, "mode", "pc")
    if mode == "pi":
        dsn = getattr(settings, "db_url", None)
        if not dsn:
            raise ValueError("Modo pi requer DB_URL configurado (settings.db_url).")
        return PgStorage(dsn)
    return SqliteStorage(getattr(settings, "db_path", "./sentinela.db"))
