#!/usr/bin/env bash
#!/usr/bin/env bash

TARGET=$1

if [ -z "$TARGET" ]; then
 echo "Uso: ./scan.sh <ip ou rede>"
 exit 1
fi

echo "Iniciando scan em $TARGET..."

nmap -sV -oX scan_result.xml "$TARGET"

echo "Scan finalizado"
echo "Rodando análise..."

python3 analyze.py scan_result.xml

set -euo pipefail
IFS=$'\n\t'

# -------------------------
# Cores
# -------------------------
RED="\033[0;31m"
GREEN="\033[0;32m"
YELLOW="\033[1;33m"
BLUE="\033[0;34m"
NC="\033[0m"

# -------------------------
# Defaults
# -------------------------
PORTS="1-1024"
OUTPUT=""
THREADS=5
VERSION_SCAN=false
LOG_FILE="scan_$(date +%F_%H-%M).log"

# -------------------------
# Usage
# -------------------------
usage() {
echo -e "${BLUE}Uso:${NC} $0 [-p ports] [-o output] [-t threads] [-v] <rede/CIDR>"
echo "Exemplo:"
echo "$0 -p 22,80 -t 10 -v 192.168.0.0/24"
exit 1
}

# -------------------------
# Argumentos
# -------------------------
while getopts ":p:o:t:vh" opt; do
case $opt in
p) PORTS="$OPTARG" ;;
o) OUTPUT="$OPTARG" ;;
t) THREADS="$OPTARG" ;;
v) VERSION_SCAN=true ;;
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

# -------------------------
# Validação de rede
# -------------------------
if command -v python3 >/dev/null; then
python3 - <<EOF
import ipaddress,sys
try:
 ipaddress.ip_network("$REDE", strict=False)
except:
 sys.exit(1)
EOF
if [ $? -ne 0 ]; then
echo -e "${RED}Rede inválida${NC}"
exit 1
fi
fi

# -------------------------
# Arquivo temporário
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

nmap -sn "$REDE" -oG - | awk '/Up/{print $2}' > "$HOSTS_FILE" 2>>"$LOG_FILE"

if [ ! -s "$HOSTS_FILE" ]; then
echo -e "${RED}Nenhum host ativo encontrado${NC}"
exit 0
fi

TOTAL=$(wc -l < "$HOSTS_FILE")

echo -e "${GREEN}Hosts encontrados:${NC} $TOTAL"
cat "$HOSTS_FILE"

echo ""

# -------------------------
# Função de scan
# -------------------------
scan_host() {

host=$1

if $VERSION_SCAN; then
CMD="nmap -Pn -sV --open -p $PORTS $host"
else
CMD="nmap -Pn --open -p $PORTS $host"
fi

if [ -n "$OUTPUT" ]; then
$CMD >> "$OUTPUT" 2>>"$LOG_FILE"
else
$CMD
fi

}

export -f scan_host
export PORTS VERSION_SCAN OUTPUT LOG_FILE

# -------------------------
# Scan paralelo
# -------------------------
echo -e "${YELLOW}[2] Escaneando portas...${NC}"

cat "$HOSTS_FILE" | xargs -I{} -P "$THREADS" bash -c 'scan_host "$@"' _ {}

echo ""
echo -e "${GREEN}Scan finalizado!${NC}"
echo -e "Log: $LOG_FILE"