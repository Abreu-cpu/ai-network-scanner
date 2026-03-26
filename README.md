# 🚀 Network Scanner (Nmap + CVE Analyzer)

Uma ferramenta de análise de rede automatizada que combina **Bash, Nmap e Python** para identificar serviços expostos, avaliar riscos e consultar vulnerabilidades conhecidas (CVEs) em tempo real.

O projeto integra varredura de rede com análise estruturada e enriquecimento de dados via API externa, fornecendo um fluxo completo de inspeção de segurança.

---

## ⚡ Funcionalidades

- 🔍 Varredura de rede com Nmap
- 📊 Detecção de portas abertas e serviços ativos
- 🧠 Análise local de risco baseada em serviços
- 🌐 Integração com API de vulnerabilidades (Vulners)
- 🛡️ Identificação de CVEs com score e referência
- 📁 Exportação de relatórios estruturados em JSON
- ⚠️ Tratamento de erros e fallback de consultas

---

## 🧱 Arquitetura

Target IP / Network
        ↓
     Nmap Scan
        ↓
   XML Output
        ↓
 Python Analyzer
        ↓
 Risk Analysis + CVE Lookup
        ↓
 Terminal Output + JSON Report

---

🛠️ Tecnologias Utilizadas

| Tecnologia  | Função                                        |
| ----------- | --------------------------------------------- |
| Bash        | Automação do fluxo de execução                |
| Python      | Processamento, análise e integração           |
| Nmap        | Varredura de rede e identificação de serviços |
| XML         | Estrutura de dados do scan                    |
| Vulners API | Consulta de vulnerabilidades                  |


📦 Estrutura do Projeto

network-vulnerability-scanner/
├── scan.sh                # Script principal de varredura
├── analyze.py             # Analisador de resultados + integração CVE
├── knowledge_base.py      # Base local de risco por serviço
├── scan_*.xml             # Resultados do Nmap (gerados automaticamente)
├── report_*.json          # Relatórios estruturados (gerados automaticamente)


⚙️ Instalação

Requisitos:
- Linux / Kali Linux / WSL
- Python 3.x
- Nmap

Instalação do Nmap:
$ sudo apt update
$ sudo apt install nmap


🚀 Uso

Tornar o script executável:
$ chmod +x scan.sh

Execução básica:
$ ./scan.sh 192.168.1.1

Execução com parâmetros:
$ ./scan.sh -p 22,80,443 -t 10 192.168.1.1


🔑 Configuração da API

Para habilitar a consulta de vulnerabilidades:
$ export VULNERS_API_KEY="SUA_CHAVE_AQUI"


📊 Exemplo de Saída

Porta 22 → ssh (protocol 2.0)
Risco: Alto
Recomendação: Desabilite login root e use chaves SSH.

[!] 5 CVE(s) encontrada(s):
- CVE-XXXX: descrição (Score: X.X)


📁 Exemplo de Relatório JSON

{
  "host": "192.168.1.1",
  "source_xml": "scan_192.168.1.1.xml",
  "ports": [
    {
      "port": "22",
      "service": "ssh",
      "product": "",
      "version": "",
      "risk": "Alto",
      "recommendation": "Desabilite login root e use chaves SSH.",
      "cve_status": "ok",
      "cves": []
    }
  ]
}


🎯 Objetivo

Este projeto foi desenvolvido com foco em:
- Segurança de redes
- Fundamentos de pentest
- Automação de processos de análise
- Integração com APIs externas
- Processamento de dados estruturados


⚠️ Aviso Legal

Esta ferramenta deve ser utilizada apenas em ambientes autorizados.
O uso indevido pode violar legislações e políticas de segurança.


🚀 Roadmap / Melhorias Futuras

- Geração de relatório em HTML
- Dashboard web interativo
- Melhor correlação de CVEs por versão de serviço
- Integração com múltiplas fontes (NVD, ExploitDB)
- Sistema avançado de scoring de risco
- Detecção automatizada de falsos positivos


👨‍💻 Autor

Julio


