#!/bin/bash
# ============================================================
#  Fractia Sandbox Manager
#  Lanzador del entorno Docker de pruebas de seguridad
# ============================================================

set -e

# ── Colores ───────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# ── Config ────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="$SCRIPT_DIR/docker-compose.sandbox.yml"
SANDBOX_CONTAINER="fractia-sandbox"

# ── Funciones de UI ───────────────────────────────────────

banner() {
  clear
  echo -e "${CYAN}"
  echo "  ╔═══════════════════════════════════════════════════╗"
  echo "  ║                                                   ║"
  echo "  ║    ██████╗ ███████╗ █████╗ ███╗  ██╗██████╗      ║"
  echo "  ║    ██╔══██╗██╔════╝██╔══██╗████╗ ██║╚════██╗     ║"
  echo "  ║    ██████╔╝███████╗███████║██╔██╗██║  ▄███╔╝     ║"
  echo "  ║    ██╔══██╗╚════██║██╔══██║██║╚████║  ▀▀══╝      ║"
  echo "  ║    ██║  ██║███████║██║  ██║██║ ╚███║  ██╗        ║"
  echo "  ║    ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚══╝  ╚═╝       ║"
  echo "  ║                                                   ║"
  echo -e "  ║${YELLOW}            ⚡  SANDBOX  MANAGER  ⚡${CYAN}             ║"
  echo "  ╚═══════════════════════════════════════════════════╝"
  echo -e "${NC}"
}

info()    { echo -e "  ${CYAN}[+]${NC} $1"; }
success() { echo -e "  ${GREEN}[✓]${NC} $1"; }
warn()    { echo -e "  ${YELLOW}[!]${NC} $1"; }
error()   { echo -e "  ${RED}[✗]${NC} $1"; }
step()    { echo -e "\n  ${MAGENTA}──────────────────────────────────────${NC}"; echo -e "  ${BOLD}$1${NC}"; }

check_docker() {
  if ! command -v docker &>/dev/null; then
    error "Docker no está instalado."
    echo -e "  ${DIM}Instala Docker: https://docs.docker.com/get-docker/${NC}"
    exit 1
  fi

  if ! docker info &>/dev/null; then
    error "El daemon de Docker no está corriendo."
    warn "Inicia Docker Desktop o ejecuta: sudo systemctl start docker"
    exit 1
  fi

  if ! command -v docker compose &>/dev/null && ! docker-compose version &>/dev/null 2>&1; then
    error "docker compose no está disponible."
    exit 1
  fi
}

compose_cmd() {
  if command -v docker compose &>/dev/null; then
    docker compose -f "$COMPOSE_FILE" "$@"
  else
    docker-compose -f "$COMPOSE_FILE" "$@"
  fi
}

status_check() {
  echo ""
  echo -e "  ${BOLD}Estado del laboratorio:${NC}"
  echo ""

  services=("fractia-sandbox" "fractia-dvwa" "fractia-juiceshop" "fractia-vulnapi" "fractia-webgoat")
  names=("Sandbox (tools)" "DVWA" "Juice Shop" "VulnAPI" "WebGoat")
  ports=("—" "http://localhost:8080" "http://localhost:3000" "http://localhost:4000" "http://localhost:8888")

  for i in "${!services[@]}"; do
    status=$(docker inspect --format='{{.State.Status}}' "${services[$i]}" 2>/dev/null || echo "stopped")
    if [ "$status" = "running" ]; then
      echo -e "  ${GREEN}●${NC} ${names[$i]} ${DIM}${ports[$i]}${NC}"
    else
      echo -e "  ${RED}○${NC} ${names[$i]} ${DIM}(detenido)${NC}"
    fi
  done
  echo ""
}

# ── Opciones del menú ─────────────────────────────────────

build_images() {
  step "Construyendo imágenes Docker..."
  info "Esto puede tardar unos minutos la primera vez."
  echo ""
  compose_cmd build --no-cache
  success "Imágenes construidas correctamente."
}

start_sandbox() {
  step "Levantando el laboratorio completo..."
  compose_cmd up -d
  echo ""
  success "Laboratorio iniciado."
  echo ""
  echo -e "  ${BOLD}Targets disponibles:${NC}"
  echo -e "  ${DIM}──────────────────────────────────────${NC}"
  echo -e "  ${GREEN}DVWA${NC}        →  http://localhost:8080    ${DIM}(admin/password)${NC}"
  echo -e "  ${GREEN}Juice Shop${NC}  →  http://localhost:3000"
  echo -e "  ${GREEN}VulnAPI${NC}     →  http://localhost:4000    ${DIM}(custom para Fractia)${NC}"
  echo -e "  ${GREEN}WebGoat${NC}     →  http://localhost:8888/WebGoat"
  echo ""
  warn "Desde dentro del sandbox usa los hostnames: dvwa, juiceshop, vulnapi, webgoat"
}

open_shell() {
  status=$(docker inspect --format='{{.State.Status}}' "$SANDBOX_CONTAINER" 2>/dev/null || echo "stopped")

  if [ "$status" != "running" ]; then
    warn "El sandbox no está corriendo. Iniciando..."
    compose_cmd up -d
    sleep 2
  fi

  step "Abriendo shell en el sandbox..."
  echo -e "  ${DIM}Escribe 'exit' para salir del contenedor${NC}"
  echo -e "  ${DIM}El proyecto Fractia está montado en /fractia${NC}"
  echo ""
  docker exec -it "$SANDBOX_CONTAINER" /bin/bash
}

run_recon() {
  echo ""
  echo -e "  ${BOLD}Targets disponibles:${NC}"
  echo "  [1] DVWA          → http://dvwa"
  echo "  [2] Juice Shop    → http://juiceshop:3000"
  echo "  [3] VulnAPI       → http://vulnapi:4000"
  echo "  [4] URL custom"
  echo ""
  read -rp "  Elige target [1-4]: " choice

  case $choice in
    1) TARGET="http://dvwa" ;;
    2) TARGET="http://juiceshop:3000" ;;
    3) TARGET="http://vulnapi:4000" ;;
    4) read -rp "  URL: " TARGET ;;
    *) warn "Opción inválida."; return ;;
  esac

  status=$(docker inspect --format='{{.State.Status}}' "$SANDBOX_CONTAINER" 2>/dev/null || echo "stopped")
  if [ "$status" != "running" ]; then
    warn "Sandbox no activo. Iniciando..."; compose_cmd up -d; sleep 2
  fi

  step "Ejecutando recon contra $TARGET..."
  docker exec -it "$SANDBOX_CONTAINER" recon "$TARGET"
}

run_fractia_audit() {
  echo ""
  echo -e "  ${BOLD}Auditar código con Fractia:${NC}"
  echo ""
  echo -e "  ${DIM}El proyecto está montado en /fractia dentro del sandbox.${NC}"
  echo -e "  ${DIM}Puedes apuntar PROJECT_ROOT a /fractia/vulnapi para auditar la VulnAPI.${NC}"
  echo ""
  read -rp "  ¿Abrir shell en modo auditoría? [s/N]: " confirm
  if [[ "$confirm" =~ ^[sS]$ ]]; then
    docker exec -it "$SANDBOX_CONTAINER" bash -c \
      "cd /fractia && PROJECT_ROOT=/fractia/vulnapi node fractia.js"
  fi
}

stop_sandbox() {
  step "Deteniendo el laboratorio..."
  compose_cmd stop
  success "Laboratorio detenido. Los datos persisten."
}

nuke_sandbox() {
  echo ""
  warn "${RED}ADVERTENCIA: Esto eliminará todos los contenedores, imágenes y volúmenes del sandbox.${NC}"
  read -rp "  ¿Confirmas? Escribe 'BORRAR' para continuar: " confirm

  if [ "$confirm" = "BORRAR" ]; then
    step "Eliminando todo..."
    compose_cmd down --volumes --rmi local 2>/dev/null || true
    docker volume rm fractia-sandbox-results 2>/dev/null || true
    success "Sandbox eliminado completamente."
  else
    info "Operación cancelada."
  fi
}

show_logs() {
  echo ""
  echo -e "  ${BOLD}Logs de qué servicio?${NC}"
  echo "  [1] sandbox   [2] dvwa   [3] juiceshop   [4] vulnapi   [5] webgoat   [6] todos"
  read -rp "  Elige [1-6]: " choice

  case $choice in
    1) compose_cmd logs -f sandbox ;;
    2) compose_cmd logs -f dvwa ;;
    3) compose_cmd logs -f juiceshop ;;
    4) compose_cmd logs -f vulnapi ;;
    5) compose_cmd logs -f webgoat ;;
    6) compose_cmd logs -f ;;
    *) warn "Opción inválida." ;;
  esac
}

# ── Menú principal ────────────────────────────────────────

main_menu() {
  while true; do
    banner
    status_check

    echo -e "  ${BOLD}¿Qué quieres hacer?${NC}"
    echo ""
    echo -e "  ${CYAN}[1]${NC} Construir imágenes              ${DIM}(primera vez o tras cambios)${NC}"
    echo -e "  ${CYAN}[2]${NC} Iniciar laboratorio completo     ${DIM}(todos los targets)${NC}"
    echo -e "  ${CYAN}[3]${NC} Abrir shell en el sandbox        ${DIM}(bash con todas las tools)${NC}"
    echo -e "  ${CYAN}[4]${NC} Recon rápido de un target        ${DIM}(nmap + whatweb + nikto)${NC}"
    echo -e "  ${CYAN}[5]${NC} Auditar VulnAPI con Fractia      ${DIM}(SAST sobre la app custom)${NC}"
    echo -e "  ${CYAN}[6]${NC} Ver logs                         ${DIM}(de cualquier servicio)${NC}"
    echo -e "  ${CYAN}[7]${NC} Detener laboratorio"
    echo -e "  ${RED}[8]${NC} Eliminar todo                    ${DIM}(contenedores + imágenes)${NC}"
    echo ""
    echo -e "  ${DIM}[Q] Salir${NC}"
    echo ""
    read -rp "  → " choice
    echo ""

    case "${choice,,}" in
      1) build_images ;;
      2) start_sandbox ;;
      3) open_shell ;;
      4) run_recon ;;
      5) run_fractia_audit ;;
      6) show_logs ;;
      7) stop_sandbox ;;
      8) nuke_sandbox ;;
      q|quit|exit) info "Bye."; echo ""; exit 0 ;;
      *) warn "Opción no válida." ;;
    esac

    echo ""
    read -rp "  Pulsa Enter para continuar..." _
  done
}

# ── Entry point ───────────────────────────────────────────
check_docker

# Modo argumento directo (para llamarlo desde fractia.js o npm)
case "${1:-}" in
  build)   check_docker; build_images ;;
  up)      check_docker; start_sandbox ;;
  shell)   check_docker; open_shell ;;
  down)    check_docker; stop_sandbox ;;
  status)  check_docker; status_check ;;
  nuke)    check_docker; nuke_sandbox ;;
  *)       main_menu ;;
esac
