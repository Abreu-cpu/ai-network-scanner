# AI Network Scanner

AI Network Scanner é uma ferramenta simples de automação de análise de rede que combina Bash, Nmap e Python para realizar scans de rede e gerar explicações automáticas sobre os serviços detectados.

O projeto executa um scan de portas utilizando Nmap e depois analisa os resultados usando Python, gerando um pequeno relatório explicando os serviços encontrados e possíveis riscos de segurança.

## Como funciona

Fluxo da ferramenta:

Target IP / Network
↓
Nmap Scan
↓
Resultado em XML
↓
Python Analyzer
↓
Relatório de segurança

O scanner identifica portas abertas e serviços rodando em um host ou rede e fornece uma explicação básica sobre cada serviço.

## Tecnologias utilizadas

- Bash scripting
- Python
- Nmap
- XML parsing

Ferramenta principal utilizada para escaneamento:
Nmap (https://nmap.org)

## Estrutura do projeto

ai-network-scanner/
│
├── scan.sh # Script que executa o scan com Nmap
├── analyze.py # Script Python que analisa o resultado
├── knowledge_base.py # Base de conhecimento de serviços
└── scan_result.xml # Resultado do scan (gerado automaticamente)


## Instalação

Requisitos:

- Linux / Kali Linux / WSL
- Python 3
- Nmap

Instale o Nmap:

sudo apt update
sudo apt install nmap


## Como usar

Dê permissão de execução ao script:

chmod +x scan.sh

Execute o scanner:
./scan.sh 192.168.1.1


ou escaneie uma rede inteira:
./scan.sh 192.168.0.0/24


## Exemplo de saída
Host: 192.168.1.10

Porta 22 → ssh
Descrição: Secure Shell usado para administração remota.
Risco: Baixo se configurado corretamente.

Porta 23 → telnet
Descrição: Protocolo antigo para acesso remoto.
Risco: ALTO - transmite credenciais sem criptografia.

Porta 80 → http
Descrição: Servidor web padrão.


## Objetivo do projeto

Este projeto foi criado com fins educacionais para estudar:

- automação de ferramentas de segurança
- análise de serviços de rede
- scripting em Bash
- parsing de dados em Python
- fundamentos de segurança de redes

## Aviso

Esta ferramenta deve ser utilizada apenas em redes onde você possui autorização para realizar testes.

Escaneamento de redes sem permissão pode violar políticas ou legislações locais.

## Possíveis melhorias

- geração de relatório em HTML
- detecção automática de vulnerabilidades
- integração com bancos de CVE
- análise automática com IA

## Autor

Julio
