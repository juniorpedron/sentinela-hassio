# Sentinela — Add-on do Home Assistant

Monitor da rede doméstica que roda 24/7 no mesmo Pi do Home Assistant, dentro da
UI autenticada do HA (Ingress). Lê uma **cópia** do tráfego pela porta espelhada
do switch (SPAN) e mostra quem está na rede e o que cada aparelho acessa.

## O que este build faz (v0.3.1)

**Inventário e identificação**
- Descoberta por ARP, ping, mDNS e SSDP; fabricante pelo MAC.
- Nome que o aparelho anuncia por **DHCP**, classe do fabricante e sistema provável.
- **User-Agent** de requisições HTTP sem criptografia (indica sistema/aparelho).
- Tipo do aparelho (celular, computador, TV, videogame, casa inteligente…) por
  heurística; o painel mostra de onde veio o palpite.
- MAC privado (aleatório) sinalizado; rede interna do HA fica fora da lista.

**Um aparelho, vários MACs**
- O rastreio é por MAC. Celulares usam MAC privado, que pode mudar; cada MAC novo
  viraria um aparelho novo. O Sentinela junta os registros do mesmo aparelho:
  automaticamente quando o nome DHCP é o mesmo (e não é genérico, como "iPhone"),
  ou manualmente pelo painel ("é o mesmo aparelho que…"). Nada é apagado e o
  vínculo pode ser desfeito.

**Tráfego por dispositivo (só metadados)**
- **DNS**: nome consultado e tipo (A, AAAA, HTTPS…).
- **TLS**: nome do site (SNI) em qualquer porta.
- **HTTP/3 (QUIC)**: início de conexão, com o nome vindo do DNS.
- **TCP**: toda conexão nova, em qualquer porta, com o serviço provável.
- **Volume**: bytes enviados e recebidos por conexão TCP, somados por hora, por
  aparelho e por serviço.
- **Entrada**: conexão iniciada de fora para um aparelho da casa gera alerta.

## Limites honestos

- O conteúdo cifrado **nunca** é lido; só nomes, portas e tamanhos.
- O volume cobre **apenas TCP** e só entra na conta quando a conexão termina.
  Vídeo por HTTP/3 (YouTube, parte do Netflix) aparece como conexão, sem volume.
- Aparelho que usa DNS cifrado (DoH/DoT) não tem as consultas vistas; o nome do
  site ainda aparece pelo TLS.
- Tráfego IPv6 é atribuído pelo MAC, e só depois de o aparelho ter sido visto
  por IPv4.
- Sem o espelhamento (SPAN) configurado no switch, só há inventário.

## Segurança

- **Ingress:** o painel é servido dentro do Home Assistant (login do HA); nenhuma
  porta extra é aberta na rede.
- **Privilégios:** `host_network`, `NET_RAW` (leitura de pacotes) e `NET_ADMIN`
  (colocar a interface do espelho em modo promíscuo). Sem acesso a pastas do host.
- A captura é **passiva**: a interface do espelho só recebe cópia, não transmite.
- Os dados ficam no volume `/data` do add-on (SQLite local, sem nuvem).
- Alterações no painel (rótulo, confiança) exigem o `admin_token`. **Troque o
  valor padrão** nas opções do add-on.

## Opções

| Opção | Padrão | O quê |
|---|---|---|
| `capture_iface` | `enu1u1` | Interface ligada à porta espelhada do switch. |
| `lan_cidr` | *(vazio)* | Faixa da rede; vazio = detecta sozinho. |
| `exclude_macs` | `[]` | MACs fora da captura profunda (continuam no inventário). |
| `retention_days` | `60` | Retenção desejada (a limpeza automática ainda não foi implementada). |
| `admin_token` | `1120` | Token para alterações no painel — trocar. |
| `ha_webhook` | *(vazio)* | Id de um webhook do Home Assistant. Quando preenchido, o Sentinela avisa o HA (em `127.0.0.1:8123`, sem sair da rede) cerca de 3 min depois de ver um aparelho inédito: nome, tipo, IP, MAC, fabricante. Não avisa de aparelho já rotulado nem de aparelho conhecido que só trocou de MAC privado; no máximo 6 avisos por hora. O id funciona como senha do aviso — não publicar. |

## Instalação e atualização

O add-on é instalado a partir do repositório `juniorpedron/sentinela-hassio`
(Configurações → Add-ons → Loja → Repositórios). Para atualizar: **Verificar
atualizações** na loja e **Atualizar** no add-on; o log mostra o motivo se o
build falhar. O filtro de captura novo tem fallback automático para o antigo se
o Pi o recusar (o painel mostra "filtro rico" ou "filtro básico").
