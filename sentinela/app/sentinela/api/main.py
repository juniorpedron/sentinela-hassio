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
import ipaddress
import json
from datetime import datetime, timedelta, timezone
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


class AliasBody(BaseModel):
    """Corpo do POST /api/devices/{id}/alias: id do aparelho principal, ou null para desvincular."""

    primary_id: str | None = None


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

    from sentinela.common import identify
    from sentinela.common.services import friendly

    try:
        lan_net = ipaddress.ip_network(settings.lan_cidr, strict=False)
    except ValueError:
        lan_net = None

    def _ativo(dev: dict, horas: int) -> bool:
        try:
            visto = datetime.fromisoformat(str(dev.get("last_seen")))
        except ValueError:
            return False
        if visto.tzinfo is None:
            visto = visto.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) - visto <= timedelta(hours=horas)

    async def _grupos() -> tuple[list[dict], dict[str, str]]:
        """Aparelhos (registros do mesmo aparelho ja unidos) + mapa registro -> aparelho."""
        return identify.agrupar(await app.state.storage.list_devices())

    async def _membros(device_id: str) -> list[str]:
        """Ids de todos os registros (MACs) do aparelho a que ``device_id`` pertence."""
        aparelhos, mapa = await _grupos()
        raiz = mapa.get(device_id, device_id)
        for a in aparelhos:
            if a["id"] == raiz:
                return [m["id"] for m in a["members"]]
        return [device_id]

    async def _devices(hours: int = 24, internal: bool = False) -> list[dict]:
        """Aparelhos com nome/tipo derivados + atividade e volume na janela."""
        st = app.state.storage
        aparelhos, _mapa = await _grupos()
        act = await st.activity_by_device(hours)
        uso = {u["device_id"]: u for u in await st.usage_by_device(hours)}
        agora = datetime.now(timezone.utc)
        out = []
        for d in aparelhos:
            e = identify.enrich(d, lan_net)
            if e["internal"] and not internal:
                continue
            ids = [m["id"] for m in d["members"]]
            e["flows"] = sum(act.get(i, {}).get("flows", 0) for i in ids)
            e["dns"] = sum(act.get(i, {}).get("dns", 0) for i in ids)
            e["bytes_up"] = sum((uso.get(i, {}).get("bytes_up") or 0) for i in ids)
            e["bytes_down"] = sum((uso.get(i, {}).get("bytes_down") or 0) for i in ids)
            e["conns"] = sum((uso.get(i, {}).get("conns") or 0) for i in ids)
            e["active"] = _ativo(d, hours)
            e["capturado"] = bool(e["flows"] or e["dns"] or e["conns"])
            e["macs"] = len(ids)
            try:
                primeiro = datetime.fromisoformat(str(d.get("first_seen")))
                if primeiro.tzinfo is None:
                    primeiro = primeiro.replace(tzinfo=timezone.utc)
                e["novo"] = agora - primeiro <= timedelta(hours=48)
            except ValueError:
                e["novo"] = False
            out.append(e)
        return out

    async def _por_aparelho(consulta, device_id: str | None, limit: int) -> list[dict]:
        """Roda ``consulta(device_id=, limit=)`` para cada MAC do aparelho e junta por data."""
        if not device_id:
            return await consulta(device_id=None, limit=limit)
        linhas: list[dict] = []
        for i in await _membros(device_id):
            linhas.extend(await consulta(device_id=i, limit=limit))
        linhas.sort(key=lambda r: str(r.get("ts") or ""), reverse=True)
        return linhas[:limit]

    def _servico(host: str | None) -> tuple[str, str]:
        if not host:
            return ("Sem nome", "Desconhecido")
        return friendly(host)

    def _captura() -> dict | None:
        c = getattr(app.state, "controls", None)
        cap = getattr(c, "capture", None) if c is not None else None
        if not cap:
            return None
        return {
            "iface": cap.get("iface"), "filtro": cap.get("filtro"),
            "stats": dict(cap.get("stats") or {}),
            "gateways": len(cap.get("gateways") or ()),
            "conexoes_abertas": len(cap.get("conexoes_abertas") or ()),
            "nomes_dns": len(cap.get("nomes_dns") or ()),
            "grandes": list(cap.get("grandes") or ()),
        }

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

    # O painel (html/js/css) deve ser sempre revalidado: sem isto o navegador
    # guarda a versao antiga por dias depois de uma atualizacao do add-on.
    @app.middleware("http")
    async def _sem_cache_do_painel(request: Request, call_next):
        resp = await call_next(request)
        if not request.url.path.startswith("/api/"):
            resp.headers["Cache-Control"] = "no-cache"
        return resp

    # ---- Rotas /api/* ----------------------------------------------------

    @app.get("/api/health")
    async def health() -> dict:
        """Ping de saude; devolve o modo de operacao (pi|pc)."""
        c = getattr(app.state, "controls", None)
        return {"status": "ok", "mode": settings.mode, "readonly": bool(getattr(c, "readonly", False)),
                "capture": _captura()}

    @app.get("/api/devices")
    async def devices(
        hours: int = Query(default=24, ge=1, le=720),
        internal: bool = Query(default=False),
    ) -> list[dict]:
        """Dispositivos da LAN com nome de exibicao, tipo, atividade e volume.

        ``internal=1`` inclui tambem o que nao e da LAN (rede docker do HA).
        """
        return await _devices(hours=hours, internal=internal)

    @app.get("/api/devices/{device_id}")
    async def device_detail(device_id: str) -> dict:
        """Detalhe de um dispositivo por id (com os campos derivados)."""
        if await app.state.storage.get_device(device_id) is None:
            raise HTTPException(status_code=404, detail="Dispositivo nao encontrado")
        aparelhos, mapa = await _grupos()
        raiz = mapa.get(device_id, device_id)
        for a in aparelhos:
            if a["id"] == raiz:
                e = identify.enrich(a, lan_net)
                e["macs"] = len(a["members"])
                return e
        raise HTTPException(status_code=404, detail="Dispositivo nao encontrado")

    @app.post("/api/devices/{device_id}/alias", dependencies=[Depends(_require_token)])
    async def set_alias(device_id: str, body: AliasBody) -> dict:
        """Diz que este registro (MAC) e o MESMO aparelho que ``primary_id``.

        ``primary_id`` nulo desfaz o vinculo. Nada e apagado: so o agrupamento muda.
        """
        st = app.state.storage
        dev = await st.get_device(device_id)
        if dev is None:
            raise HTTPException(status_code=404, detail="Dispositivo nao encontrado")
        if body.primary_id is None:
            await st.set_device_meta_key(device_id, "alias_of", None)
            await st.add_event(device_id=device_id, severity="info", type="device.alias",
                               title="Vinculo de aparelho desfeito", detail=dev.get("mac"))
            return {"ok": True, "alias_of": None}
        _ap, mapa = await _grupos()
        alvo = mapa.get(body.primary_id)
        if alvo is None:
            raise HTTPException(status_code=404, detail="Aparelho principal nao encontrado")
        if alvo == mapa.get(device_id) and alvo != device_id:
            return {"ok": True, "alias_of": alvo}
        if alvo == device_id:
            raise HTTPException(status_code=422, detail="Um aparelho nao pode ser vinculado a si mesmo")
        # se este registro era principal de outros, eles passam a apontar para o novo principal
        for outro, raiz in mapa.items():
            if raiz == device_id and outro != device_id:
                await st.set_device_meta_key(outro, "alias_of", alvo)
        await st.set_device_meta_key(device_id, "alias_of", alvo)
        principal = await st.get_device(alvo)
        await st.add_event(
            device_id=alvo, severity="info", type="device.alias",
            title="MAC vinculado a um aparelho conhecido",
            detail=f"{dev.get('mac')} -> {(principal or {}).get('label') or (principal or {}).get('mac')}",
        )
        return {"ok": True, "alias_of": alvo}

    @app.get("/api/overview")
    async def overview(hours: int = Query(default=24, ge=1, le=720)) -> dict:
        """Resumo da janela: ativos, volume, quem mais usa e o que mais e usado."""
        devs = await _devices(hours=hours)
        nomes = {d["id"]: d for d in devs}
        _ap, mapa = await _grupos()
        ativos = [d for d in devs if d["active"]]
        top_dev = sorted(devs, key=lambda d: (d["bytes_up"] + d["bytes_down"], d["flows"] + d["dns"]),
                         reverse=True)
        servicos: dict = {}
        for u in await app.state.storage.usage_by_host(hours=hours, limit=2000):
            ap_id = mapa.get(u["device_id"], u["device_id"])
            if ap_id not in nomes:
                continue
            nome, cat = _servico(u["host"])
            s = servicos.setdefault(nome, {"name": nome, "category": cat, "bytes_up": 0,
                                           "bytes_down": 0, "conns": 0, "devices": set()})
            s["bytes_up"] += u["bytes_up"] or 0
            s["bytes_down"] += u["bytes_down"] or 0
            s["conns"] += u["conns"] or 0
            s["devices"].add(ap_id)
        top_svc = sorted(servicos.values(), key=lambda x: x["bytes_up"] + x["bytes_down"], reverse=True)
        for x in top_svc:
            x["devices"] = len(x["devices"])
        return {
            "hours": hours,
            "devices_total": len(devs),
            "devices_active": len(ativos),
            "unknown_active": sum(1 for d in ativos if (d.get("trust_state") or "unknown") == "unknown"),
            "unnamed_active": sum(1 for d in ativos if not d["named"]),
            "new_devices": [
                {"id": d["id"], "name": d["display_name"], "kind": d["kind"], "ip4": d.get("ip4"),
                 "first_seen": d.get("first_seen"), "trust_state": d.get("trust_state"),
                 "private_mac": d["private_mac"], "vendor": d.get("mac_vendor")}
                for d in devs if d["novo"] and d["active"]
            ],
            "bytes_up": sum(d["bytes_up"] for d in devs),
            "bytes_down": sum(d["bytes_down"] for d in devs),
            "top_devices": [
                {"id": d["id"], "name": d["display_name"], "kind": d["kind"],
                 "bytes_up": d["bytes_up"], "bytes_down": d["bytes_down"],
                 "flows": d["flows"], "dns": d["dns"]}
                for d in top_dev[:10] if d["capturado"]
            ],
            "top_services": top_svc[:12],
            "alerts_24h": len([
                e for e in await app.state.storage.list_events(severity="warning", limit=500)
                if str(e.get("ts")) > (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
            ]) + len([
                e for e in await app.state.storage.list_events(severity="critical", limit=500)
                if str(e.get("ts")) > (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
            ]),
            "capture": _captura(),
        }

    @app.get("/api/usage")
    async def usage(
        hours: int = Query(default=24, ge=1, le=720),
        device_id: str | None = Query(default=None),
        limit: int = Query(default=200, ge=1, le=2000),
    ) -> list[dict]:
        """Volume por dispositivo x servico (bytes medidos nas conexoes TCP)."""
        nomes = {d["id"]: d for d in await _devices(hours=hours, internal=True)}
        _ap, mapa = await _grupos()
        membros = set(await _membros(device_id)) if device_id else None
        soma: dict = {}
        for u in await app.state.storage.usage_by_host(hours=hours, limit=5000):
            if membros is not None and u["device_id"] not in membros:
                continue
            did = mapa.get(u["device_id"], u["device_id"])
            r = soma.setdefault((did, u["host"]), {"bytes_up": 0, "bytes_down": 0, "conns": 0})
            r["bytes_up"] += u["bytes_up"] or 0
            r["bytes_down"] += u["bytes_down"] or 0
            r["conns"] += u["conns"] or 0
        out = []
        for (did, host), r in soma.items():
            d = nomes.get(did, {})
            nome, cat = _servico(host)
            out.append({"device_id": did, "device": d.get("display_name") or "?", "kind": d.get("kind"),
                        "host": host, "service": nome, "category": cat, **r})
        out.sort(key=lambda x: x["bytes_up"] + x["bytes_down"], reverse=True)
        return out[:limit]

    @app.get("/api/traffic")
    async def traffic(
        device_id: str | None = Query(default=None),
        limit: int = Query(default=300, ge=1, le=2000),
    ) -> list[dict]:
        """Conexoes recentes ja identificadas: quem (dispositivo) acessou o que (servico)."""
        nomes = {d["id"]: d for d in await _devices(internal=True)}
        _ap, mapa = await _grupos()
        out = []
        for f in await _por_aparelho(app.state.storage.recent_flows, device_id, limit):
            ap_id = mapa.get(f.get("device_id"), f.get("device_id"))
            d = nomes.get(ap_id, {})
            host = f.get("sni")
            nome, cat = _servico(host or f.get("dst_ip"))
            out.append({
                "ts": f.get("ts"), "device_id": ap_id,
                "device": d.get("display_name") or f.get("src_ip") or "?", "kind": d.get("kind"),
                "service": nome, "category": cat, "host": host, "dst_ip": f.get("dst_ip"),
                "dst_port": f.get("dst_port"), "proto": f.get("proto"), "app": f.get("app_proto"),
            })
        return out

    @app.get("/api/flows")
    async def flows(
        device_id: str | None = Query(default=None),
        limit: int = Query(default=100, ge=1, le=1000),
    ) -> list[dict]:
        """Fluxos recentes, opcionalmente filtrados por aparelho (todos os MACs dele)."""
        return await _por_aparelho(app.state.storage.recent_flows, device_id, limit)

    @app.get("/api/dns")
    async def dns(
        device_id: str | None = Query(default=None),
        limit: int = Query(default=100, ge=1, le=1000),
    ) -> list[dict]:
        """Consultas DNS recentes, opcionalmente filtradas por aparelho (todos os MACs dele)."""
        return await _por_aparelho(app.state.storage.recent_dns, device_id, limit)

    @app.get("/api/events")
    async def events(
        severity: str | None = Query(default=None),
        limit: int = Query(default=100, ge=1, le=1000),
    ) -> list[dict]:
        """Eventos recentes, opcionalmente filtrados por severidade."""
        return await app.state.storage.list_events(severity=severity, limit=limit)

    @app.get("/api/stats")
    async def stats() -> dict:
        """Resumo agregado (dispositivos, desconhecidos, flows/dns/events 24h).

        ``devices``/``unknown_devices`` contam so a LAN (sem a rede interna do HA).
        """
        s = dict(await app.state.storage.stats())
        devs = await _devices()
        s["devices"] = len(devs)
        s["unknown_devices"] = sum(1 for d in devs if (d.get("trust_state") or "unknown") == "unknown")
        s["devices_active"] = sum(1 for d in devs if d["active"])
        return s

    @app.get("/api/timeline")
    async def timeline(hours: int = Query(default=24, ge=1, le=168)) -> list[dict]:
        """Serie temporal por hora (flows/dns/eventos/bytes) para o grafico."""
        linhas = await app.state.storage.timeline(hours=hours)
        vol = await app.state.storage.usage_by_hour(hours=hours)
        vistos = {l["bucket"] for l in linhas}
        for b in vol:
            if b not in vistos:
                linhas.append({"bucket": b, "flows": 0, "dns": 0, "events": 0})
        for l in linhas:
            l["bytes"] = vol.get(l["bucket"], 0)
        linhas.sort(key=lambda l: l["bucket"])
        return linhas

    def _dt(v) -> datetime | None:
        try:
            d = datetime.fromisoformat(str(v))
        except (ValueError, TypeError):
            return None
        return d if d.tzinfo else d.replace(tzinfo=timezone.utc)

    @app.get("/api/now")
    async def now(minutes: int = Query(default=15, ge=1, le=240)) -> dict:
        """Quem esta fazendo o que AGORA: aparelhos com atividade nos ultimos minutos."""
        st = app.state.storage
        corte = datetime.now(timezone.utc) - timedelta(minutes=minutes)
        nomes = {d["id"]: d for d in await _devices()}
        _ap, mapa = await _grupos()
        por_ap: dict = {}
        for kind, linhas, campo in (
            ("flow", await st.recent_flows(limit=1500), "sni"),
            ("dns", await st.recent_dns(limit=1500), "qname"),
        ):
            for r in linhas:
                t = _dt(r.get("ts"))
                if t is None or t < corte:
                    continue
                ap = mapa.get(r.get("device_id"), r.get("device_id"))
                if ap not in nomes:
                    continue
                host = r.get(campo) or (r.get("dst_ip") if kind == "flow" else None)
                if not host or str(host).endswith((".arpa", ".local")):
                    continue
                nome, cat = _servico(host)
                e = por_ap.setdefault(ap, {"ultimo": t, "svc": {}, "n": 0})
                e["n"] += 1
                e["ultimo"] = max(e["ultimo"], t)
                sv = e["svc"].setdefault(nome, {"name": nome, "category": cat, "count": 0, "conexao": False})
                sv["count"] += 1
                sv["conexao"] = sv["conexao"] or kind == "flow"
        saida = []
        for ap, e in por_ap.items():
            d = nomes[ap]
            svcs = sorted(e["svc"].values(), key=lambda x: (x["conexao"], x["count"]), reverse=True)
            # servicos de sistema ficam por ultimo: o que interessa e o que a pessoa esta usando
            svcs.sort(key=lambda x: x["category"] in ("Sistema", "Infra", "CDN", "Publicidade", "Desconhecido", "Outro"))
            saida.append({"id": ap, "name": d["display_name"], "kind": d["kind"], "trust_state": d.get("trust_state"),
                          "last": e["ultimo"].isoformat(), "registros": e["n"], "services": svcs[:6],
                          "mais": max(0, len(svcs) - 6)})
        saida.sort(key=lambda x: x["registros"], reverse=True)
        return {"minutes": minutes, "devices": saida}

    @app.get("/api/categories")
    async def categories(hours: int = Query(default=24, ge=1, le=720)) -> list[dict]:
        """Para onde vai o trafego: conexoes e volume por categoria de servico."""
        st = app.state.storage
        corte = datetime.now(timezone.utc) - timedelta(hours=hours)
        cats: dict = {}

        def c(nome: str) -> dict:
            return cats.setdefault(nome, {"category": nome, "conns": 0, "bytes": 0, "services": {}})

        for f in await st.recent_flows(limit=5000):
            t = _dt(f.get("ts"))
            if t is None or t < corte:
                continue
            nome, cat = _servico(f.get("sni") or f.get("dst_ip"))
            x = c(cat)
            x["conns"] += 1
            x["services"][nome] = x["services"].get(nome, 0) + 1
        for u in await st.usage_by_host(hours=hours, limit=5000):
            _n, cat = _servico(u["host"])
            c(cat)["bytes"] += (u["bytes_up"] or 0) + (u["bytes_down"] or 0)
        out = []
        for x in cats.values():
            top = sorted(x["services"].items(), key=lambda kv: kv[1], reverse=True)[:4]
            out.append({"category": x["category"], "conns": x["conns"], "bytes": x["bytes"],
                        "top": [k for k, _v in top]})
        out.sort(key=lambda x: x["conns"], reverse=True)
        return out

    @app.get("/api/insights")
    async def insights() -> list[dict]:
        """O que merece atencao, em frases curtas. sev: ok | info | warn | alert."""
        st = app.state.storage
        devs = await _devices()
        ativos = [d for d in devs if d["active"]]
        itens: list[dict] = []

        quarentena = [d for d in devs if d.get("trust_state") == "quarantine" and d["active"]]
        if quarentena:
            itens.append({"sev": "alert", "title": f"{len(quarentena)} aparelho(s) em quarentena estão ativos",
                          "text": ", ".join(d["display_name"] for d in quarentena[:4]), "view": "dispositivos"})

        corte = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
        entradas = [e for e in await st.list_events(severity="warning", limit=500)
                    if e.get("type") == "inbound.tcp" and str(e.get("ts")) > corte]
        if entradas:
            alvos = sorted({nomes_ev for nomes_ev in (
                next((d["display_name"] for d in devs if any(m["id"] == e.get("device_id") for m in d["members"])), None)
                for e in entradas) if nomes_ev})
            itens.append({"sev": "warn", "title": f"{len(entradas)} tentativa(s) de conexão vindas de fora em 24 h",
                          "text": "Alvo: " + (", ".join(alvos[:4]) or "?") + ". Normalmente o roteador bloqueia; vale conferir se não é esperado.",
                          "view": "eventos"})

        novos = [d for d in ativos if d["novo"] and (d.get("trust_state") or "unknown") == "unknown"]
        if novos:
            itens.append({"sev": "warn", "title": f"{len(novos)} aparelho(s) novo(s) ainda sem classificação",
                          "text": ", ".join(d["display_name"] for d in novos[:4]) + ". Abra e diga se é confiável.",
                          "view": "dispositivos"})

        desconhecidos = [d for d in ativos if (d.get("trust_state") or "unknown") == "unknown" and not d["novo"]]
        if desconhecidos:
            itens.append({"sev": "info", "title": f"{len(desconhecidos)} aparelho(s) antigo(s) sem classificação",
                          "text": ", ".join(d["display_name"] for d in desconhecidos[:5]), "view": "dispositivos"})

        com_vol = sorted(devs, key=lambda d: d["bytes_up"] + d["bytes_down"], reverse=True)
        total = sum(d["bytes_up"] + d["bytes_down"] for d in devs)
        if total > 0 and com_vol:
            top = com_vol[0]
            pct = round(100 * (top["bytes_up"] + top["bytes_down"]) / total)
            itens.append({"sev": "info", "title": f"{top['display_name']} responde por {pct}% do volume medido em 24 h",
                          "text": "Volume medido só nas conexões TCP encerradas; vídeo por HTTP/3 não entra na conta.",
                          "device_id": top["id"]})

        envio = [d for d in devs if d["bytes_up"] > 200_000_000 and d["bytes_up"] > 2 * d["bytes_down"]]
        for d in envio[:2]:
            itens.append({"sev": "info", "title": f"{d['display_name']} enviou mais do que recebeu",
                          "text": "Envio acima de 200 MB em 24 h. Costuma ser backup, sincronização ou acesso remoto.",
                          "device_id": d["id"]})

        cap = _captura()
        if cap is None:
            itens.append({"sev": "warn", "title": "A captura não está ativa",
                          "text": "Só há inventário; tráfego por aparelho não está sendo registrado.", "view": "geral"})
        elif cap.get("filtro") != "rico" or (cap.get("stats") or {}).get("erros"):
            itens.append({"sev": "info", "title": "Captura em modo reduzido",
                          "text": f"filtro {cap.get('filtro')}, {(cap.get('stats') or {}).get('erros', 0)} pacotes com erro.",
                          "view": "geral"})

        if not any(i["sev"] in ("alert", "warn") for i in itens):
            itens.insert(0, {"sev": "ok", "title": "Nada fora do normal",
                             "text": f"{len(ativos)} aparelhos ativos em 24 h, todos os alertas zerados."})
        return itens

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
    async def graph(
        limit: int = Query(default=40, ge=5, le=200),
        hours: int = Query(default=168, ge=1, le=8760),
    ) -> dict:
        """Mapa da rede: roteador central + dispositivos vistos na janela + servicos."""
        from sentinela.common.services import _is_ip

        flows = await app.state.storage.recent_flows(limit=4000)
        devices = [d for d in await _devices(hours=hours) if d["active"]]
        devmap = {d["id"]: d for d in devices}
        _ap, mapa = await _grupos()

        agg: dict = {}
        svc_meta: dict = {}
        for f in flows:
            did = mapa.get(f.get("device_id"), f.get("device_id"))
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
                "label": d["display_name"],
                "kind": "device", "trust_state": d.get("trust_state"), "count": 0,
                "group": d["kind_group"], "device_kind": d["kind"],
                "meta": {
                    "tipo": d["kind_label"], "sistema": d.get("os"),
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
                        devmap[d]["display_name"] for d in m["devices"] if d in devmap
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
