"""Controles de runtime do Sentinela, alternaveis pelo painel (ex.: sniffer)."""

from __future__ import annotations


class RuntimeControls:
    """Flags mutaveis em tempo real, compartilhadas entre API e sensores."""

    def __init__(self, sniffer_enabled: bool = True, readonly: bool = False) -> None:
        self.sniffer_enabled = sniffer_enabled
        self.readonly = readonly  # somente-leitura: bloqueia acoes ativas (ARP)

    def snapshot(self) -> dict:
        return {"sniffer_enabled": self.sniffer_enabled, "readonly": self.readonly}
