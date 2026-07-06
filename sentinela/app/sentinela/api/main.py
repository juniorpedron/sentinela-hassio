"""API FastAPI do Sentinela.

Expoe as rotas /api/* do contrato e o feed ao vivo via WebSocket /api/live.
O mesmo app serve os dois modos (Pi e PC); a instancia de Storage e
injetada em app.state.storage pelo entrypoint (ex.: run_pc.py).

Uso tipico:
    from sentinela.api.main import create_app
    app = create_app(storage)
"""

from __future__ import annotations

import asyncio
import csv
import io
import json
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from sentinela.config import get_settings

# Diretorio do dashboard estatico (HTML/CSS/JS puro), montado em "/".
DASHBOARD_DIR = Path(__file__).resolve().parent.parent / "dashboard"


class DeviceUpdate(BaseModel):
    """Corpo aceito no POST /api/devices/{device_id} (todos opcionais)."""

    label: str | None = None
    trust_state: str | None = None
    profile: str | None = None


class SnifferToggle(BaseModel):
    """Corpo do POST /api/control/sniffer."""

    enabled: bool


class InterceptToggle(BaseModel):
    """Corpo do POST /api/intercept/{device_id}."""

    enabled: bool = True
    dur: int = 180


# Valores permitidos para trust_state conforme o modelo de dados.
_TRUST_STATES = {"unknown", "trusted", "quarantine"}


async def _require_token(x_sentinela_token: str | None = Header(default=None)) -> None:
    """Valida o header X-Sentinela-Token contra o ADMIN_TOKEN das settings.

    Usado como dependencia nas rotas de mutacao. Levanta 401 se ausente/invalido.
    """
    settings = get_settings()
    if not x_sentinela_token or x_sentinela_token != settings.admin_token:
        raise HTTPException(status_code=401, detail="Token invalido ou ausente")


async def _no_readonly(request: Request) -> None:
    """Bloqueia acoes ativas quando em modo somente-leitura."""
    c = getattr(request.app.state, "controls", None)
    if c is not None and getattr(c, "readonly", False):
        raise HTTPException(status_code=403, detail="Modo somente leitura: acoes ativas desabilitadas nesta rede.")


def create_app(storage, controls=None) -> FastAPI:
    """Cria e configura o app FastAPI usando a instancia de Storage informada.

    O storage e guardado em app.state.storage e usado por todas as rotas.
    """
    settings = get_settings()
    app = FastAPI(title="Sentinela", version="1.0")
    app.state.storage = storage
    app.state.controls = controls

    # CORS liberado apenas para localhost (dashboard local + WS).
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[
            f"http://127.0.0.1:{settings.api_port}",
            f"http://localhost:{settings.api_port}",
            "http://127.0.0.1",
            "http://localhost",
        ],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ---- Rotas /api/* ----------------------------------------------------

    @app.get("/api/health")
    async def health() -> dict:
        """Ping de saude; devolve o modo de operacao (pi|pc)."""
        c = getattr(app.state, "controls", None)
        return {"status": "ok", "mode": settings.mode, "readonly": bool(getattr(c, "readonly", False))}

    @app.get("/api/devices")
    async def devices() -> list[dict]:
        """Lista todos os dispositivos conhecidos."""
        return await app.state.storage.list_devices()

    @app.get("/api/devices/{device_id}")
    async def device_detail(device_id: str) -> dict:
        """Detalhe de um dispositivo por id."""
        dev = await app.state.storage.get_device(device_id)
        if dev is None:
            raise HTTPException(status_code=404, detail="Dispositivo nao encontrado")
        return dev

    @app.get("/api/flows")
    async def flows(
        device_id: str | None = Query(default=None),
        limit: int = Query(default=100, ge=1, le=1000),
    ) -> list[dict]:
        """Fluxos recentes, opcionalmente filtrados por dispositivo."""
        return await app.state.storage.recent_flows(device_id=device_id, limit=limit)

    @app.get("/api/dns")
    async def dns(
        device_id: str | None = Query(default=None),
        limit: int = Query(default=100, ge=1, le=1000),
    ) -> list[dict]:
        """Consultas DNS recentes, opcionalmente filtradas por dispositivo."""
        return await app.state.storage.recent_dns(device_id=device_id, limit=limit)

    @app.get("/api/events")
    async def events(
        severity: str | None = Query(default=None),
        limit: int = Query(default=100, ge=1, le=1000),
    ) -> list[dict]:
        """Eventos recentes, opcionalmente filtrados por severidade."""
        return await app.state.storage.list_events(severity=severity, limit=limit)

    @app.get("/api/stats")
    async def stats() -> dict:
        """Resumo agregado (dispositivos, desconhecidos, flows/dns/events 24h)."""
        return await app.state.storage.stats()

    @app.get("/api/timeline")
    async def timeline(hours: int = Query(default=24, ge=1, le=168)) -> list[dict]:
        """Serie temporal por hora (flows/dns/eventos) para o grafico."""
        return await app.state.storage.timeline(hours=hours)

    @app.get("/api/top")
    async def top(
        kind: str = Query(default="domains"),
        hours: int = Query(default=24, ge=1, le=168),
        limit: int = Query(default=10, ge=1, le=100),
    ) -> list[dict]:
        """Ranking dos mais frequentes: kind = domains | apps | hosts | talkers."""
        return await app.state.storage.top(kind=kind, hours=hours, limit=limit)

    @app.get("/api/export")
    async def export(
        kind: str = Query(default="flows"),
        limit: int = Query(default=1000, ge=1, le=100000),
    ) -> Response:
        """Exporta dados em CSV (kind = flows | dns | events | devices)."""
        if kind == "flows":
            linhas = await app.state.storage.recent_flows(limit=limit)
        elif kind == "dns":
            linhas = await app.state.storage.recent_dns(limit=limit)
        elif kind == "events":
            linhas = await app.state.storage.list_events(limit=limit)
        elif kind == "devices":
            linhas = await app.state.storage.list_devices()
        else:
            raise HTTPException(status_code=422, detail="kind invalido")
        buf = io.StringIO()
        if linhas:
            writer = csv.DictWriter(buf, fieldnames=list(linhas[0].keys()))
            writer.writeheader()
            writer.writerows(linhas)
        return Response(
            content=buf.getvalue(),
            media_type="text/csv; charset=utf-8",
            headers={
                "Content-Disposition": f'attachment; filename="sentinela-{kind}.csv"'
            },
        )

    @app.post("/api/devices/{device_id}", dependencies=[Depends(_require_token)])
    async def update_device(device_id: str, body: DeviceUpdate) -> dict:
        """Atualiza label/trust_state/profile de um dispositivo (protegido por token)."""
        dev = await app.state.storage.get_device(device_id)
        if dev is None:
            raise HTTPException(status_code=404, detail="Dispositivo nao encontrado")

        if body.trust_state is not None and body.trust_state not in _TRUST_STATES:
            raise HTTPException(
                status_code=422,
                detail=f"trust_state deve ser um de {sorted(_TRUST_STATES)}",
            )

        await app.state.storage.update_device(
            device_id,
            label=body.label,
            trust_state=body.trust_state,
            profile=body.profile,
        )
        # Rastreabilidade: registra a mudanca como evento auditavel.
        mudancas = []
        if body.trust_state is not None and body.trust_state != dev.get("trust_state"):
            mudancas.append(f"confianca {dev.get('trust_state')} -> {body.trust_state}")
        if body.label is not None:
            mudancas.append(f"label='{body.label}'")
        if body.profile is not None:
            mudancas.append(f"perfil={body.profile}")
        await app.state.storage.add_event(
            device_id=device_id,
            severity="info",
            type="device.update",
            title="Dispositivo atualizado via painel",
            detail="; ".join(mudancas) or "sem mudancas",
        )
        return await app.state.storage.get_device(device_id)

    @app.get("/api/control")
    async def get_control() -> dict:
        """Estado dos controles de runtime (ex.: sniffer ligado/desligado)."""
        c = getattr(app.state, "controls", None)
        return c.snapshot() if c else {"sniffer_enabled": None}

    @app.post("/api/control/sniffer", dependencies=[Depends(_require_token)])
    async def set_sniffer(body: SnifferToggle) -> dict:
        """Liga/desliga o sniffer L2 em tempo real (protegido por token)."""
        c = getattr(app.state, "controls", None)
        if c is None:
            raise HTTPException(status_code=503, detail="Controles indisponiveis")
        c.sniffer_enabled = bool(body.enabled)
        return c.snapshot()

    @app.get("/api/graph")
    async def graph(limit: int = Query(default=40, ge=5, le=200)) -> dict:
        """Mapa da rede: roteador central + TODOS os dispositivos + servicos."""
        from sentinela.common.services import _is_ip, friendly

        flows = await app.state.storage.recent_flows(limit=4000)
        devices = await app.state.storage.list_devices()
        devmap = {d["id"]: d for d in devices}

        agg: dict = {}
        svc_meta: dict = {}
        for f in flows:
            did = f.get("device_id")
            host = f.get("sni")
            if not host or _is_ip(host) or "." not in host:
                continue
            nome, cat = friendly(host)
            agg[(did, nome)] = agg.get((did, nome), 0) + 1
            m = svc_meta.get(nome)
            if m is None:
                m = svc_meta[nome] = {"category": cat, "count": 0, "hosts": set(), "devices": set()}
            m["count"] += 1
            m["hosts"].add(host)
            if did:
                m["devices"].add(did)

        top = sorted(svc_meta.items(), key=lambda kv: kv[1]["count"], reverse=True)[:limit]
        top_names = {n for n, _ in top}

        nodes: list = []
        edges: list = []

        # No central: o roteador / rede local.
        GW_ID = "gw:rede"
        nodes.append({
            "id": GW_ID, "label": "Roteador", "kind": "gateway", "count": 0,
            "meta": {"tipo": "roteador / rede local", "dispositivos": len(devices)},
        })

        # TODOS os dispositivos viram nos, ligados ao roteador.
        for d in devices:
            nodes.append({
                "id": d["id"],
                "label": d.get("label") or d.get("hostname") or d.get("mac") or d["id"],
                "kind": "device", "trust_state": d.get("trust_state"), "count": 0,
                "meta": {
                    "mac": d.get("mac"), "ipv4": d.get("ip4"), "ipv6": d.get("ip6"),
                    "fabricante": d.get("mac_vendor"), "hostname": d.get("hostname"),
                    "confianca": d.get("trust_state"), "ultimo_visto": d.get("last_seen"),
                },
            })
            edges.append({"source": d["id"], "target": GW_ID, "weight": 1})

        # Servicos (dominios reais) + arestas dispositivo -> servico.
        for nome, m in top:
            nodes.append({
                "id": "svc:" + nome, "label": nome, "kind": "service",
                "category": m["category"], "count": m["count"],
                "meta": {
                    "categoria": m["category"], "conexoes": m["count"],
                    "hosts": sorted(m["hosts"])[:6],
                    "dispositivos": sorted(
                        (devmap.get(d, {}).get("label") or devmap.get(d, {}).get("hostname")
                         or devmap.get(d, {}).get("mac") or d) for d in m["devices"]
                    )[:8],
                },
            })
        for (did, nome), w in agg.items():
            if did and nome in top_names and did in devmap:
                edges.append({"source": did, "target": "svc:" + nome, "weight": w})

        return {"nodes": nodes, "edges": edges,
                "total_services": len(svc_meta), "total_devices": len(devices)}

    @app.get("/api/intercept")
    async def intercept_status() -> dict:
        """Lista as interceptacoes ARP ativas (device + tempo restante)."""
        m = getattr(app.state, "intercept", None)
        return m.status() if m else {"ativos": []}

    @app.post("/api/intercept/{device_id}", dependencies=[Depends(_require_token), Depends(_no_readonly)])
    async def intercept_toggle(device_id: str, body: InterceptToggle) -> dict:
        """Liga/desliga a interceptacao ARP de um dispositivo (protegido)."""
        m = getattr(app.state, "intercept", None)
        if m is None:
            raise HTTPException(status_code=503, detail="Interceptacao indisponivel")
        if body.enabled:
            return await m.start(device_id, dur=max(30, min(900, body.dur)))
        return await m.stop(device_id)

    # ---- WebSocket do feed ao vivo --------------------------------------

    @app.websocket("/api/live")
    async def live(ws: WebSocket) -> None:
        """Feed ao vivo: repassa cada msg do storage como JSON.

        Registra um listener no storage que empurra mensagens para uma fila
        asyncio; a corrotina consome a fila e envia ao cliente. Mantem
        keepalive por ping periodico e remove o listener no disconnect.
        """
        await ws.accept()
        loop = asyncio.get_running_loop()
        queue: asyncio.Queue = asyncio.Queue(maxsize=1000)

        def _listener(msg: dict) -> None:
            # Chamado pelo storage (possivelmente de outra task); agenda o put
            # de forma thread-safe na loop do WebSocket.
            try:
                loop.call_soon_threadsafe(queue.put_nowait, msg)
            except asyncio.QueueFull:
                # Fila cheia: descarta a mensagem para nao travar o produtor.
                pass

        app.state.storage.add_listener(_listener)
        try:
            while True:
                try:
                    # Espera uma mensagem; se estourar o timeout, envia keepalive.
                    msg = await asyncio.wait_for(queue.get(), timeout=25.0)
                except asyncio.TimeoutError:
                    await ws.send_text(json.dumps({"kind": "ping"}))
                    continue
                await ws.send_text(json.dumps(msg, default=str))
        except WebSocketDisconnect:
            pass
        finally:
            app.state.storage.remove_listener(_listener)

    # ---- Dashboard estatico ---------------------------------------------
    # Montado por ultimo para nao capturar as rotas /api/*.
    if DASHBOARD_DIR.is_dir():
        app.mount("/", StaticFiles(directory=str(DASHBOARD_DIR), html=True), name="dashboard")
    # TODO(sentinela): se o diretorio do dashboard nao existir ainda, apenas
    # as rotas de API ficam disponiveis.

    return app
