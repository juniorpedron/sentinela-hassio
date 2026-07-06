"""Entrypoint do MODO PI (captura via SPAN) do Sentinela.

Roda no Raspberry Pi (add-on do Home Assistant). Combina:
  - DESCOBERTA ATIVA na interface de gerencia (ARP/ping/mDNS/SSDP) -> inventario
    e nomes dos dispositivos.
  - CAPTURA no espelho (SPAN) -> DNS/SNI reais atribuidos a CADA dispositivo.
  - Dashboard/API servido para o Home Assistant (ingress).

Uso:  python -m sentinela.sensors.pi_span.run_pi
"""

from __future__ import annotations

import asyncio
import logging

import uvicorn

from sentinela.api.main import create_app
from sentinela.common.controls import RuntimeControls
from sentinela.common.storage import SqliteStorage
from sentinela.config import get_settings
from sentinela.sensors.pc_local import discovery, passive_listen
from sentinela.sensors.pi_span import capture

log = logging.getLogger("sentinela.run_pi")


async def _serve() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    settings = get_settings()

    storage = SqliteStorage(settings.db_path)
    await storage.connect()

    controls = RuntimeControls(sniffer_enabled=True)
    app = create_app(storage, controls)

    # Alertas via webhook (opcional).
    if settings.alert_webhook:
        try:
            from sentinela.sensors.pc_local.run_pc import _make_alert_listener
            storage.add_listener(
                _make_alert_listener(asyncio.get_running_loop(), settings.alert_webhook)
            )
        except Exception:  # pragma: no cover - alerta e opcional
            pass

    tasks = [
        asyncio.create_task(discovery.run_forever(storage, settings), name="discovery"),
        asyncio.create_task(passive_listen.run_forever(storage, settings), name="passive"),
        asyncio.create_task(capture.run_forever(storage, settings, controls), name="span-capture"),
    ]

    print("=" * 60)
    print(" Sentinela - MODO PI (captura via SPAN)")
    print(f" Interface de captura : {settings.capture_iface}")
    print(f" LAN                  : {settings.lan_cidr}")
    print(f" Dashboard/API        : :{settings.api_port}")
    print(f" Excluidos da captura : {len(settings.exclude_macs)} MAC(s)")
    print("=" * 60)

    config = uvicorn.Config(
        app, host=settings.api_host, port=settings.api_port,
        log_level="info", loop="asyncio",
    )
    server = uvicorn.Server(config)
    try:
        await server.serve()
    finally:
        for t in tasks:
            t.cancel()
        for t in tasks:
            try:
                await t
            except asyncio.CancelledError:
                pass
        await storage.close()


def main() -> None:
    try:
        asyncio.run(_serve())
    except KeyboardInterrupt:
        print("\nSentinela encerrado.")


if __name__ == "__main__":
    main()
