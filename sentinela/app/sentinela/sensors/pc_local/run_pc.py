"""Entrypoint do MODO PC (portatil/standalone) do Sentinela.

Roda no notebook para observar "ao vivo" a rede onde o equipamento esta
conectado. Usa SQLite (sem docker, sem Npcap obrigatorio), sobe a mesma API
FastAPI/dashboard do MODO PI e dispara a task de descoberta ativa.

Uso:
    python -m sentinela.sensors.pc_local.run_pc

Ao subir, imprime a URL (http://127.0.0.1:8787 por padrao) e o ADMIN_TOKEN,
necessario no header X-Sentinela-Token para qualquer mutacao via API.

LIMITE HONESTO: o MODO PC so ve o proprio trafego + broadcast/multicast + o que
descobre ativamente. Para ver o trafego unicast de TODA a rede, use o MODO PI
com espelhamento de porta (SPAN).
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import urllib.request

import uvicorn

from sentinela.api.main import create_app
from sentinela.common.storage import SqliteStorage
from sentinela.config import get_settings
from sentinela.sensors.pc_local import discovery, own_activity, passive_listen, sniffer
from sentinela.sensors.pc_local.intercept import InterceptManager
from sentinela.common.controls import RuntimeControls

log = logging.getLogger("sentinela.run_pc")


async def _post_webhook(webhook: str, payload: dict) -> None:
    """Envia um evento de alerta para o webhook (bloqueante em executor)."""

    def _do() -> None:
        try:
            data = json.dumps(
                {"text": payload.get("title", "alerta"), "event": payload},
                default=str,
            ).encode("utf-8")
            req = urllib.request.Request(
                webhook, data=data, headers={"Content-Type": "application/json"}
            )
            urllib.request.urlopen(req, timeout=5).read()
        except Exception as exc:  # um alerta nunca derruba o coletor
            log.debug("webhook de alerta falhou: %s", exc)

    await asyncio.get_running_loop().run_in_executor(None, _do)


def _make_alert_listener(loop: asyncio.AbstractEventLoop, webhook: str):
    """Listener que dispara o webhook para eventos warning/critical."""

    def listener(msg: dict) -> None:
        if msg.get("kind") != "event":
            return
        p = msg.get("payload", {}) or {}
        if (p.get("severity") or "").lower() not in ("warning", "critical"):
            return
        loop.call_soon_threadsafe(
            lambda: asyncio.ensure_future(_post_webhook(webhook, p))
        )

    return listener


async def _detectar_readonly(settings) -> tuple[bool, str]:
    """Somente-leitura automatico quando NAO estamos na rede de casa."""
    modo = (getattr(settings, "readonly", "auto") or "auto").lower()
    if modo in ("1", "true", "on", "sim"):
        return True, "forcado por SENTINELA_READONLY=1"
    if modo in ("0", "false", "off", "nao"):
        return False, "desativado por SENTINELA_READONLY=0"
    alvo = (getattr(settings, "home_gateway_mac", "") or "").lower().replace("-", ":")
    if not alvo:
        return False, "sem HOME_GATEWAY_MAC — modo ativo"
    def _gw_mac():
        from scapy.all import conf, getmacbyip
        gw = conf.route.route("0.0.0.0")[2]
        return (getmacbyip(gw) or "").lower(), gw
    try:
        mac, gw = await asyncio.wait_for(
            asyncio.get_running_loop().run_in_executor(None, _gw_mac), timeout=20)
    except Exception as exc:
        return False, f"nao detectei o gateway ({exc}) — modo ativo"
    ro = bool(mac) and mac != alvo
    return ro, f"gateway {gw} mac={mac or '?'} (casa={alvo})"


async def _serve() -> None:
    """Sobe storage SQLite, API + dashboard e a descoberta ativa em paralelo."""
    settings = get_settings()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    # Storage SQLite (aplica db/schema_sqlite.sql no connect).
    storage = SqliteStorage(settings.db_path)
    await storage.connect()

    # Controles de runtime (ligar/desligar o sniffer pelo painel).
    controls = RuntimeControls(
        sniffer_enabled=os.environ.get("SENTINELA_SNIFFER", "1") != "0"
    )

    # API FastAPI + StaticFiles do dashboard; injeta storage em app.state.
    app = create_app(storage, controls)

    # Modo SOMENTE LEITURA automatico fora da rede de casa (so visualizacao).
    _ro, _motivo = await _detectar_readonly(settings)
    controls.readonly = _ro
    log.info("modo: %s | %s", "SOMENTE LEITURA" if _ro else "ATIVO", _motivo)

    # Gerenciador de interceptacao ao vivo por dispositivo (ARP MITM).
    intercept_mgr = InterceptManager(storage, settings)
    intercept_mgr.loop = asyncio.get_running_loop()
    app.state.intercept = intercept_mgr

    # Alertas: empurra eventos warning/critical para o webhook, se configurado.
    if settings.alert_webhook:
        storage.add_listener(
            _make_alert_listener(asyncio.get_running_loop(), settings.alert_webhook)
        )
        log.info("webhook de alertas ativo: %s", settings.alert_webhook)

    # Task de descoberta ativa (ARP + ping sweep + mDNS + SSDP + rDNS + OUI).
    disc_task = asyncio.create_task(
        discovery.run_forever(storage, settings),
        name="sentinela-discovery",
    )

    # Task de captura da atividade do PROPRIO PC (conexoes psutil + cache DNS).
    own_task = asyncio.create_task(
        own_activity.run_forever(storage, settings),
        name="sentinela-own-activity",
    )

    # Task de escuta PASSIVA de multicast (SSDP/LLMNR) -- enriquece os OUTROS.
    passive_task = asyncio.create_task(
        passive_listen.run_forever(storage, settings),
        name="sentinela-passive",
    )

    # Task de sniffer L2 (scapy/Npcap) -- DHCP/ARP/DNS/SNI reais; no-op sem Npcap.
    sniffer_task = asyncio.create_task(
        sniffer.run_forever(storage, settings, controls),
        name="sentinela-sniffer",
    )

    # Banner amigavel antes de bloquear no servidor.
    url = f"http://{settings.api_host}:{settings.api_port}"
    print("=" * 60)
    print(" Sentinela - MODO PC (descoberta ativa, SQLite)")
    print("=" * 60)
    print(f" Dashboard/API : {url}")
    print(f" ADMIN_TOKEN   : {settings.admin_token}")
    print(f" LAN_CIDR      : {settings.lan_cidr}")
    print(f" Banco (SQLite): {settings.db_path}")
    print(f" Modo          : {'SOMENTE LEITURA' if controls.readonly else 'ATIVO'}")
    print("-" * 60)
    print(" LIMITE: no MODO PC so vemos o proprio trafego + broadcast/")
    print(" multicast + descoberta ativa. Trafego unicast de outros")
    print(" dispositivos exige o MODO PI com espelhamento (SPAN).")
    print("=" * 60)

    config = uvicorn.Config(
        app,
        host=settings.api_host,
        port=settings.api_port,
        log_level="info",
        loop="asyncio",
    )
    server = uvicorn.Server(config)

    try:
        await server.serve()
    finally:
        # Encerramento limpo: cancela as tasks e fecha o storage.
        for t in (disc_task, own_task, passive_task, sniffer_task):
            t.cancel()
        for t in (disc_task, own_task, passive_task, sniffer_task):
            try:
                await t
            except asyncio.CancelledError:
                pass
        try:
            await intercept_mgr.stop_all()
        except Exception:
            pass
        await storage.close()


def main() -> None:
    """Ponto de entrada sincrono para `python -m ...`."""
    try:
        asyncio.run(_serve())
    except KeyboardInterrupt:
        print("\nSentinela encerrado.")


if __name__ == "__main__":
    main()
