#!/bin/bash
# ============================================================
#  deep-scan.sh v2.0 — Auditoría "Smart & Stealth"
#  Detecta falsos positivos y evita bloqueos (IPS/WAF)
# ============================================================

TARGET=$1
UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

if [ -z "$TARGET" ]; then
  echo "Uso: deep-scan <URL>"
  exit 1
fi

CLEAN_URL=$(echo "$TARGET" | sed 's|/*$||')
HOST=$(echo "$CLEAN_URL" | sed 's|https\?://||' | cut -d'/' -f1 | cut -d':' -f1)

echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║  FRACTIA SMART AUDIT ◌ $HOST"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# --- FASE 0: Calibración (Detectar Falsos Positivos) ---
echo "  [0/6] ◌ Calibrando respuesta del servidor (404 check)..."
BASELINE_URL="$CLEAN_URL/fractia-$(date +%s)-test"
BASELINE_RES=$(curl -s -o /dev/null -w "%{http_code}:%{size_download}" -A "$UA" "$BASELINE_URL")
BASELINE_CODE=$(echo $BASELINE_RES | cut -d':' -f1)
BASELINE_SIZE=$(echo $BASELINE_RES | cut -d':' -f2)

if [ "$BASELINE_CODE" == "200" ]; then
  echo "  (!) ATENCIÓN: El servidor devuelve 200 OK para páginas inexistentes."
  echo "      Tamaño de página de error detectado: $BASELINE_SIZE bytes."
  FILTER_SIZE="--exclude-length $BASELINE_SIZE"
else
  echo "  (✓) El servidor maneja correctamente los errores 404 ($BASELINE_CODE)."
  FILTER_SIZE=""
fi
echo ""

# --- FASE 1: Tech Discovery ---
echo "  [1/6] ◌ Identificando stack tecnológico (WhatWeb)..."
whatweb -a 3 --user-agent "$UA" "$CLEAN_URL" 2>/dev/null | sed 's/^/    /'
echo ""

# --- FASE 2: Vulnerabilidades ---
echo "  [2/6] ◌ Escaneando vulnerabilidades (Nikto - Modo Stealth)..."
# Nikto con User-Agent real y delay
nikto -h "$CLEAN_URL" -useragent "$UA" -Tuning 123bde -Display 1 -maxtime 5m 2>/dev/null | grep "+" | sed 's/^/    /'
echo ""

# --- FASE 3: Directorios (Smart) ---
echo "  [3/6] ◌ Buscando directorios (Gobuster - Stealth Mode)..."
# Usamos el filtro de tamaño detectado en la Fase 0
if [ ! -z "$FILTER_SIZE" ]; then
  echo "        Filtrando automáticamente resultados de $BASELINE_SIZE bytes."
fi

gobuster dir -u "$CLEAN_URL" -w /wordlists/web-dirs.txt -a "$UA" \
  --delay 200ms -t 5 -k --quiet --no-error $FILTER_SIZE -x php,sql,bak,zip | sed 's/^/    /'
echo ""

# --- FASE 4: Puertos ---
echo "  [4/6] ◌ Escaneando puertos (Nmap)..."
IP=$(host "$HOST" 2>/dev/null | head -1 | awk '{print $NF}')
nmap -sV -F ${IP:-$HOST} 2>/dev/null | grep -E "^[0-9]|open" | sed 's/^/    /'
echo ""

# --- FASE 5: DNS ---
echo "  [5/6] ◌ Análisis DNS (Dig)..."
dig +short MX "$HOST" | sed 's/^/    · MX: /'
dig +short TXT "$HOST" | sed 's/^/    · TXT: /'
echo ""

# --- FASE 6: SSL ---
echo "  [6/6] ◌ Verificando SSL/TLS..."
if [[ "$CLEAN_URL" == https* ]]; then
  echo | openssl s_client -connect "$HOST":443 -brief 2>&1 | grep -E "Protocol|Cipher|Verification" | sed 's/^/    /'
fi

echo ""
echo "╚════════════════════════════════════════════════════════════╝"
echo "  ✓ Auditoría inteligente completada."
echo ""
