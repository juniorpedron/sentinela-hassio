# Sentinela — Add-on do Home Assistant (captura de rede via SPAN)

Repositório de add-on para o Home Assistant. Monitora a rede doméstica lendo a
porta espelhada (SPAN) do switch numa interface dedicada, capturando **DNS/SNI
por dispositivo**, inventário, presença, mapa e alertas.

## Instalar
1. Ajustes → Add-ons → Loja → ⋮ → **Repositórios** → cole a URL deste repo.
2. Instale **Sentinela (captura de rede)**.
3. Na aba **Configuration**: defina `capture_iface` (interface que recebe o
   espelho, ex.: `eth1`), a faixa `lan_cidr` e os `exclude_macs` (sensores).
4. Inicie. O painel aparece na barra lateral do Home Assistant.
