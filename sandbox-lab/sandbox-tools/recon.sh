#!/bin/bash
# ============================================================
#  recon.sh — Reconocimiento rápido de un target
#  Uso: recon <URL o IP>
# ============================================================

TARGET=$1

if [ -z "$TARGET" ]; then
  echo "Uso: recon <url-o-ip>"
  echo "Ejemplo: recon http://dvwa"
  exit 1
fi

# Extraer host del URL
HOST=$(echo "$TARGET" | sed 's|https\?://||' | cut -d'/' -f1 | cut -d':' -f1)

echo ""
echo "╔══════════════════════════════════════════╗"
echo "║  Fractia Recon → $HOST"
echo "╚══════════════════════════════════════════╝"
echo ""

echo "── [1/5] DNS / Host ──────────────────────"
host "$HOST" 2>/dev/null || echo "  (sin resolución DNS)"

echo ""
echo "── [2/5] Puertos abiertos (top 100) ──────"
nmap -T4 --top-ports 100 "$HOST" 2>/dev/null | grep -E "^[0-9]|open|filtered"

echo ""
echo "── [3/5] Tecnología web ──────────────────"
whatweb "$TARGET" 2>/dev/null || echo "  whatweb no disponible"

echo ""
echo "── [4/5] Headers HTTP ────────────────────"
curl -sI "$TARGET" 2>/dev/null | head -20

echo ""
echo "── [5/5] robots.txt ──────────────────────"
curl -s "$TARGET/robots.txt" 2>/dev/null || echo "  No encontrado"

echo ""
echo "✅ Recon completado. Usa Fractia para análisis profundo."
echo ""
