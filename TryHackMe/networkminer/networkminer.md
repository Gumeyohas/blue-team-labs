# NetworkMiner

**Plataforma:** TryHackMe  
**Categoria:** Network Forensics  
**Dificuldade:** Intermediário  
**Status:** Concluído ✅

---

## Objetivo

Utilizar o NetworkMiner para análise forense de capturas de tráfego de rede, extraindo automaticamente artefatos como arquivos transferidos, credenciais, imagens e queries DNS — sem necessidade de filtros manuais como no Wireshark.

---

## O que é o NetworkMiner

NetworkMiner é uma ferramenta de análise forense de rede (NFAT — Network Forensic Analysis Tool) que reconstrói sessões a partir de arquivos pcap e organiza os artefatos extraídos por categoria. Diferente do Wireshark, que exige filtros e inspeção manual de pacotes, o NetworkMiner automatiza a extração e apresenta os dados de forma estruturada por abas.

---

## Ferramentas Utilizadas

- NetworkMiner (versões 1.x e 2.x)

---

## Diferença entre Versões

Uma observação prática importante da room: **a versão do NetworkMiner impacta diretamente os resultados**.

| Aspecto | Versão 1.x | Versão 2.x |
|---|---|---|
| Interface | Mais simples | Mais completa |
| Parsing de protocolos | Limitado | Mais abrangente |
| Resultados em algumas abas | Podem diferir | Podem diferir |

Na prática, é necessário abrir o pcap na versão correta dependendo do que se quer investigar — algumas evidências aparecem em uma versão e não na outra.

---

## Abas Investigadas

### 1. Hosts

Lista automaticamente todos os hosts identificados no tráfego, com IP, MAC address, sistema operacional inferido (via TTL e fingerprinting) e hostname. É o ponto de partida natural de qualquer investigação — equivale ao que no Wireshark exigiria combinar filtros DHCP + NBNS + Kerberos manualmente.

---

### 2. Files (Arquivos)

Reconstrói e lista todos os arquivos transferidos durante as sessões capturadas — independente do protocolo (HTTP, FTP, SMB). Para cada arquivo, exibe:

- Nome do arquivo
- Protocolo de transferência
- IP de origem e destino
- Tamanho

É a versão automatizada do `File → Export Objects` do Wireshark, mas funciona para múltiplos protocolos simultaneamente.

**Uso investigativo:** Identificar downloads de payloads maliciosos, exfiltração de documentos ou transferências suspeitas sem precisar inspecionar pacote a pacote.

---

### 3. Images (Imagens)

Extrai e exibe as imagens transferidas no tráfego. Permite visualizar diretamente no NetworkMiner o que foi trafegado visualmente — útil para identificar conteúdo exfiltrado ou confirmar a natureza de uma sessão HTTP.

---

### 4. DNS

Lista todas as queries DNS presentes na captura, incluindo:

- Domínio consultado
- Tipo de registro (A, MX, CNAME, etc.)
- Resposta recebida
- Host que fez a consulta

**Uso investigativo:** Identificar comunicação com domínios suspeitos, DGA (Domain Generation Algorithm) ou DNS tunneling — sem precisar filtrar pacote a pacote como no Wireshark.

---

### 5. Parameters (Parâmetros)

Exibe parâmetros extraídos de requisições HTTP — campos de formulários, query strings e outros valores passados nas requisições. Útil para identificar dados submetidos em formulários web capturados no tráfego.

---

### 6. Credentials (Credenciais)

Exibe credenciais capturadas em texto claro no tráfego — usuários e senhas transmitidos por protocolos sem criptografia como HTTP Basic Auth, FTP e Telnet.

**Uso investigativo:** Confirmar comprometimento de credenciais em tráfego não criptografado, identificar usuários envolvidos em uma sessão suspeita.

> **Importante:** Esta aba só captura credenciais em texto claro. Tráfego TLS/HTTPS exige descriptografia prévia (como via KeysLogFile no Wireshark) para que as credenciais sejam visíveis.

---

## NetworkMiner vs Wireshark

| Aspecto | Wireshark | NetworkMiner |
|---|---|---|
| Abordagem | Inspeção manual por pacote | Extração automática por categoria |
| Curva de aprendizado | Mais alta (requer conhecimento de filtros) | Mais baixa (interface orientada a artefatos) |
| Flexibilidade | Alta (qualquer protocolo, qualquer campo) | Média (limitado às abas disponíveis) |
| Velocidade de triagem | Mais lenta | Mais rápida para artefatos comuns |
| Melhor uso | Investigação profunda, anomalias de protocolo | Triagem inicial, extração de artefatos |

Na prática, as duas ferramentas se complementam: NetworkMiner para triagem rápida e extração de artefatos; Wireshark para investigação profunda de anomalias.

---

## Conclusão

O NetworkMiner muda a perspectiva da análise de tráfego: em vez de pensar em pacotes, o analista pensa em **sessões e artefatos**. Isso acelera significativamente a triagem em investigações reais, onde o volume de dados é alto e o tempo é crítico. A escolha da versão correta da ferramenta e o conhecimento de cada aba são diferenciais práticos para um analista SOC.