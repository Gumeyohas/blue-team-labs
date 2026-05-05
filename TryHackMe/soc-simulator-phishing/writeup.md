# SOC Simulator — Phishing Analysis
**Plataforma:** TryHackMe  
**Categoria:** Alert Triage / SIEM  
**Ferramenta principal:** Splunk  
**Data:** Maio 2026

---

## Cenário
Simulação de ambiente SOC L1 com alertas em tempo real. 
O objetivo era identificar e classificar alertas de phishing 
e acesso a URLs blacklistadas, gerando reports de incidente 
para cada true positive.

---

## Alertas investigados

| ID | Tipo | Severidade | Classificação | Tempo |
|----|------|-----------|--------------|-------|
| 8815 | Phishing — Suspicious External Link | Medium | True Positive | 20.97 min |
| 8817 | Phishing — Suspicious External Link | Medium | True Positive | 15.97 min |
| 8816 | Firewall — Access to Blacklisted URL | High | True Positive | 8.47 min |

---

## Metodologia

**1. Triage inicial**  
Ao receber cada alerta no SIEM, analisei os metadados 
do e-mail (remetente, domínio, headers) e os logs de 
firewall para determinar a natureza do evento.

**2. Análise de logs no SIEM**  
Para cada alerta, abri o painel de logs detalhados 
diretamente na interface do SIEM. Analisei os eventos 
cronologicamente, observando timestamps, IPs de origem, 
domínios acessados e comportamento do usuário para 
entender o contexto completo de cada incidente.

**3. Validação de URLs no TryDetectMe**  
Extraí as URLs suspeitas presentes nos e-mails e as 
submeti ao TryDetectMe para análise em ambiente isolado. 
Quando a ferramenta confirmava a URL como maliciosa, 
classificava o alerta como True Positive e prosseguia 
com o report do incidente.

**4. Report do incidente**  
Documentei cada alerta com as evidências coletadas tentando usar as boas práticas dos 5Ws (Who, What, When, Where e Why) 

---

## Resultado
- True positive rate: 100%  
- False positive rate: 100%  
- Mean time to resolve: 16 minutos  

---

## Lições aprendidas
O feedback da plataforma indicou que os campos Who e Where 
precisam de mais detalhe nos reports — identificar com mais 
precisão o usuário afetado e o sistema de origem em cada alerta.

---

## MITRE ATT&CK
- T1566.001 — Phishing: Spearphishing Link  
- T1071 — Application Layer Protocol (comunicação com C2 via HTTP)
