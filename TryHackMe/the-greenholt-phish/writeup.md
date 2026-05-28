# The Greenholt Phish — Phishing Analysis
**Plataforma:** TryHackMe  
**Categoria:** Phishing Analysis  
**Ferramentas:** Email Header Analysis, OSINT (IP lookup), DNS/SPF/DMARC lookup, VirusTotal  
**Data:** Maio 2026

---

## Cenário

Um executivo de vendas da Greenholt PLC recebeu um e-mail suspeito de um suposto cliente conhecido. A mensagem apresentava diversos red flags: saudação genérica, solicitação inesperada de transferência de dinheiro e um anexo não solicitado. O comportamento não condizia com o padrão de comunicação habitual do cliente, o que levou o colaborador a escalar o caso para o SOC. O objetivo foi analisar o e-mail e determinar se era legítimo ou uma tentativa de phishing.

---

## Artefatos extraídos

| Campo | Valor |
|-------|-------|
| Transfer Reference Number (Subject) | `09674321` |
| Display name do remetente | `Mr. James Jackson` |
| Endereço de e-mail do remetente | `info@mutawamarine.com` |
| Reply-To (endereço que receberia respostas) | `info.mutawamarine@mail.com` |
| IP de origem | `192.119.71.157` |
| Proprietário do IP | `Hostwinds LLC` |
| Nome do anexo | `SWT_#09674321____PDF__.CAB` |
| SHA256 do anexo | `2e91c533615a9bb8929ac4bb76707b2444597ce063d84a4b33525e25074fff3f` |
| Tamanho do anexo (VirusTotal) | `400.26 KB` |
| Tipo real do arquivo | `RAR` |

---

## Metodologia

**1. Análise de headers**  
Abri o arquivo `challenge.eml` e inspecionei os headers para extrair os campos fundamentais. O primeiro red flag imediato foi a discrepância entre o campo `From` (`info@mutawamarine.com`) e o campo `Reply-To` (`info.mutawamarine@mail.com`): qualquer resposta do executivo seria redirecionada para um domínio diferente (`mail.com`), fora do controle da empresa real. Esse padrão é clássico de ataques BEC (Business Email Compromise).

**2. Investigação do IP de origem**  
Extraí o IP de origem dos headers (`192.119.71.157`) e realizei uma consulta WHOIS. O IP pertence à **Hostwinds LLC**, um provedor de hospedagem barato frequentemente abusado em campanhas de phishing, sem relação com a suposta empresa remetente.

**3. Verificação de SPF e DMARC**  
Realizei lookups DNS para o domínio do Return-Path:

- **SPF:** `v=spf1 include:spf.protection.outlook.com -all`  
- **DMARC:** `v=DMARC1; p=quarantine; fo=1`

Embora os registros existam, a combinação do Reply-To desviando para outro domínio com o IP de origem em infraestrutura de hospedagem genérica confirma a suspeita de spoofing/engenharia social.

**4. Análise do anexo**  
O anexo se apresentava com extensão `.CAB` — formato legítimo do Windows — mas a análise via `sha256sum` e posterior lookup no **VirusTotal** revelou que o arquivo real é do tipo **RAR**. Renomear ou usar extensões enganosas para disfarçar o tipo real é uma técnica comum de evasão de filtros de e-mail e antivírus.

---

## Resultado

O e-mail é uma tentativa de phishing com foco em **Business Email Compromise (BEC)**. Indicadores conclusivos:

- Reply-To aponta para domínio diferente do remetente (`mail.com` vs `mutawamarine.com`)
- IP de origem pertence a hosting genérico sem relação com a empresa real
- Anexo com extensão falsificada (`.CAB` mascarando um `RAR`)
- Contexto social engineered: referência a transferência de dinheiro urgente com número de referência

---

## Lições aprendidas

- Sempre verificar a discrepância entre `From`, `Reply-To` e `Return-Path` — são campos independentes e qualquer divergência é red flag imediata
- A extensão de um arquivo não define seu tipo real; usar ferramentas como `file` no Linux ou VirusTotal para confirmar o magic bytes
- IPs de origem em provedores de hospedagem genérica (Hostwinds, DigitalOcean, Vultr etc.) são indicadores de infraestrutura de ataque

---

## MITRE ATT&CK

| Técnica | Descrição |
|---------|-----------|
| T1566.001 | Phishing: Spearphishing Attachment |
| T1036.008 | Masquerading: Masquerade File Type |
| T1598 | Phishing for Information (BEC context) |
