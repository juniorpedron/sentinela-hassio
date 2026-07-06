# Sentinela — Add-on do Home Assistant

Monitor **passivo** e **seguro** da rede doméstica, rodando 24/7 no mesmo Pi do
Home Assistant, dentro da UI autenticada do HA (Ingress).

## O que este build faz (e o que NÃO faz)

**Faz (seguro, passivo):**
- Inventário de dispositivos (ARP, ping sweep, mDNS, SSDP, fabricante por OUI)
- Presença (quem está online) e **alerta de dispositivo novo**
- Mapa da rede, histórico e o tráfego do próprio Pi

**NÃO faz (removido de propósito neste build):**
- ❌ Captura de pacotes (o `scapy` **nem está instalado**)
- ❌ Interceptação ARP / MITM (impossível, não só desligado)
- ❌ Ações ativas — inicia em **somente-leitura** (`readonly: true`)

> **Limite honesto:** sem espelhamento de porta (SPAN) no switch, o Pi vê o
> mesmo que o modo PC — inventário, broadcast/multicast e o próprio tráfego.
> Para ver o tráfego unicast de **todos** os aparelhos, é preciso reposicionar o
> switch (LAN do roteador) + configurar SPAN. Aí este add-on evolui pro modo
> completo.

## Segurança

- **Ingress:** o painel é servido dentro do Home Assistant (login do HA); **nenhuma
  porta extra é aberta** na rede.
- **Privilégio mínimo:** só `NET_RAW` (para o ping da descoberta). Sem `NET_ADMIN`,
  sem `privileged`, sem acesso a pastas do host.
- **Somente-leitura por padrão.** Dados ficam no volume `/data` do add-on (SQLite
  local, sem nuvem). Ajuste a retenção nas opções.

## Instalação (add-on local)

1. No Home Assistant, instale o add-on **"Samba share"** ou **"Advanced SSH & Web
   Terminal"** para acessar a pasta `/addons`.
2. Rode `python build-addon.py` (na pasta `haos-addon/`) para montar o código.
3. Copie a pasta **`haos-addon/sentinela/`** inteira para **`/addons/sentinela/`**
   no seu Home Assistant.
4. Em **Configurações → Add-ons → Loja de Add-ons → ⋮ → Verificar atualizações**.
   O **Sentinela** aparece em "Add-ons locais".
5. Abra → **Instalar** → aguarde o build (alguns minutos no Pi).
6. **Iniciar**. Ative *"Mostrar na barra lateral"*. O painel abre pelo menu do HA.

## Opções

| Opção | Padrão | O quê |
|---|---|---|
| `readonly` | `true` | Somente-leitura (recomendado; bloqueia ações ativas). |
| `retention_days` | `30` | Dias de retenção dos registros. |
| `lan_cidr` | *(vazio)* | Faixa da rede; vazio = detecta sozinho (ex.: `192.168.100.0/24`). |

## Notas

- Testado localmente como app; a **primeira instalação no Pi precisa ser validada**
  (arquitetura, build da imagem). Se algo falhar, o log do add-on mostra o motivo.
- Para o modo completo (SPAN), fale comigo — envolve mudar a topologia do switch.
