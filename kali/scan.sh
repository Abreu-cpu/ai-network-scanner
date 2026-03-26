#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'
: "${VULNERS_API_KEY:=}"

if [ -z "${VULNERS_API_KEY:-}" ]; then
    echo -e "${YELLOW}Aviso: VULNERS_API_KEY não configurada. A consulta de CVEs será ignorada.${NC}"
fi

# -------------------------
# Cores
# -------------------------
RED="\033[0;31m"
GREEN="\033[0;32m"
YELLOW="\033[1;33m"
BLUE="\033[0;34m"
NC="\033[0m"

# -------------------------
# Configurações
# -------------------------
PORTS="1-1024"
OUTPUT_XML=""
THREADS=5
VERSION_SCAN=true
LOG_FILE="scan_$(date +%F_%H-%M).log"

# -------------------------
# Usage
# -------------------------
usage() {
    echo -e "${BLUE}Uso:${NC} $0 [-p ports] [-o output] [-t threads] <rede/CIDR>"
    echo "Exemplo:"
    echo "$0 -p 22,80,443 -t 10 192.168.0.0/24"
    exit 1
}

# -------------------------
# Argumentos
# -------------------------
while getopts ":p:o:t:h" opt; do
    case $opt in
        p) PORTS="$OPTARG" ;;
        o) OUTPUT_XML="$OPTARG" ;;
        t) THREADS="$OPTARG" ;;
        h) usage ;;
        \?) echo "Opção inválida"; usage ;;
    esac
done

shift $((OPTIND-1))

if [ $# -ne 1 ]; then
    usage
fi

REDE="$1"

# -------------------------
# Checar dependências
# -------------------------
if ! command -v nmap >/dev/null; then
    echo -e "${RED}Erro: nmap não instalado${NC}"
    exit 1
fi

if ! command -v python3 >/dev/null; then
    echo -e "${RED}Erro: python3 não instalado${NC}"
    exit 1
fi

# -------------------------
# Validação de rede
# -------------------------
if ! python3 -c "import ipaddress; ipaddress.ip_network('$REDE', strict=False)" 2>/dev/null; then
    echo -e "${RED}Rede inválida: $REDE${NC}"
    exit 1
fi

# -------------------------
# Arquivos temporários
# -------------------------
HOSTS_FILE=$(mktemp)
trap 'rm -f "$HOSTS_FILE"' EXIT

echo -e "${BLUE}================================${NC}"
echo -e "${GREEN}Network Scanner${NC}"
echo -e "${BLUE}Rede:${NC} $REDE"
echo -e "${BLUE}Portas:${NC} $PORTS"
echo -e "${BLUE}Threads:${NC} $THREADS"
echo -e "${BLUE}================================${NC}"

# -------------------------
# Descoberta de hosts
# -------------------------
echo -e "${YELLOW}[1] Descobrindo hosts ativos...${NC}"

if [[ "$REDE" != *"/"* ]]; then
    echo "$REDE" > "$HOSTS_FILE"

else
    nmap -sn -Pn "$REDE" -oG - 2>>"$LOG_FILE" | awk '/Up/{print $2}' > "$HOSTS_FILE"
fi

if [ ! -s "$HOSTS_FILE" ]; then
    echo -e "${RED}Nenhum host ativo encontrado${NC}"
    exit 0
fi

TOTAL=$(wc -l < "$HOSTS_FILE")
echo -e "${GREEN}Hosts encontrados:${NC} $TOTAL"

# -------------------------
# Função de scan
# -------------------------
scan_host() {
    local host=$1
    local output_file=$2
    
    if $VERSION_SCAN; then
        nmap -Pn -sV --open -p "$PORTS" "$host" -oX "$output_file" 2>>"$LOG_FILE"
    else
        nmap -Pn --open -p "$PORTS" "$host" -oX "$output_file" 2>>"$LOG_FILE"
    fi
}

export -f scan_host
export PORTS VERSION_SCAN OUTPUT LOG_FILE

# -------------------------
# Scan paralelo
# -------------------------
echo -e "${YELLOW}[2] Escaneando portas...${NC}"

while read -r host; do
    OUTPUT_XML="scan_${host//\//_}.xml"
    scan_host "$host" "$OUTPUT_XML"
done < "$HOSTS_FILE"

# -------------------------
# Análise de Vulnerabilidades
# -------------------------
echo -e "${YELLOW}[3] Analisando vulnerabilidades (CVE)...${NC}"

# Chama o script Python com todos os arquivos XML gerados
python3 analyze.py $(while read -r host; do echo "scan_${host//\//_}.xml"; done < "$HOSTS_FILE")

echo -e "${GREEN}Processo concluído!${NC}"