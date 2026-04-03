#!/bin/bash
# ============================================================
#  quickscan.sh — Escaneo rápido de vulnerabilidades web
#  Uso: quickscan <URL>
# ============================================================

TARGET=$1

if [ -z "$TARGET" ]; then
  echo "Uso: quickscan <url>"
  echo "Ejemplo: quickscan http://juiceshop:3000"
  exit 1
fi

echo ""
echo "╔══════════════════════════════════════════╗"
echo "║  Fractia QuickScan → $TARGET"
echo "╚══════════════════════════════════════════╝"
echo ""

echo "── Nikto (web vulnerabilities) ───────────"
nikto -h "$TARGET" -maxtime 60 2>/dev/null | tail -20

echo ""
echo "── Directorios comunes (gobuster) ────────"
gobuster dir -u "$TARGET" \
  -w /wordlists/web-dirs.txt \
  -t 20 --timeout 5s -q 2>/dev/null | head -20

echo ""
echo "── Endpoints API ─────────────────────────"
gobuster dir -u "$TARGET" \
  -w /wordlists/api-endpoints.txt \
  -t 10 --timeout 5s -q 2>/dev/null | head -10

echo ""
echo "✅ QuickScan completado."
