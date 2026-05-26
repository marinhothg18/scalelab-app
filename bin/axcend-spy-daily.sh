#!/bin/bash
# axcend-spy-daily.sh
# Roda spy-wolf automaticamente pra cada nicho master do Axcend.
# Resultados são enviados via webhook pro banco MASTER (visível pra todos os tenants).
#
# USO:
#   1. Cole o token master no AXCEND_TOKEN abaixo (gere em Axcend → Spy → Conectar Spy Wolf → marcar "master")
#   2. Edite a lista NICHOS abaixo com os ids que você quer rodar
#   3. Torne executável: chmod +x ~/Desktop/scalelab/bin/axcend-spy-daily.sh
#   4. Teste rodando manual: ~/Desktop/scalelab/bin/axcend-spy-daily.sh
#   5. Agende no cron: crontab -e
#      0 6 * * * /Users/thiagomarinho/Desktop/scalelab/bin/axcend-spy-daily.sh >> ~/axcend-spy.log 2>&1
#      (roda 6h da manhã todo dia)
#
# REQUISITOS:
#   - Claude Code CLI instalado (`claude` no PATH)
#   - Skill spy-wolf instalada no Claude Code
#   - Chrome MCP autenticado no Meta Ad Library
#   - jq instalado (`brew install jq`)

set -e

# ─── CONFIG ────────────────────────────────────────────────
AXCEND_TOKEN="COLE_SEU_TOKEN_MASTER_AQUI"
AXCEND_URL="https://app.centralaxcend.com/api/spy/import"

# Nichos pra rodar diariamente (ids do Axcend)
NICHOS=(
  "nic-memo"      # 🧠 Memória / Alzheimer
  "nic-emag"      # 🥗 Emagrecimento
  "nic-diab"      # 💉 Diabetes
  "nic-ed"        # 🍆 Disfunção erétil
  "nic-renda"     # 💰 Renda extra
)
# ────────────────────────────────────────────────────────────

if [ "$AXCEND_TOKEN" = "COLE_SEU_TOKEN_MASTER_AQUI" ]; then
  echo "❌ Configure o AXCEND_TOKEN no topo deste script."
  echo "   Gere em: Axcend → AdLib → Spy Automático → Conectar Spy Wolf (marcar master)"
  exit 1
fi

if ! command -v claude &> /dev/null; then
  echo "❌ Claude Code CLI não encontrado. Instale: https://docs.claude.com/claude-code"
  exit 1
fi

LOG_FILE="$HOME/axcend-spy-daily.log"
echo "═══════════════════════════════════════════════════" | tee -a "$LOG_FILE"
echo "🐺 Spy Wolf Daily Run · $(date '+%Y-%m-%d %H:%M:%S')" | tee -a "$LOG_FILE"
echo "═══════════════════════════════════════════════════" | tee -a "$LOG_FILE"

TOTAL=0
SUCESSO=0
FALHAS=0

for nicho in "${NICHOS[@]}"; do
  TOTAL=$((TOTAL + 1))
  echo "" | tee -a "$LOG_FILE"
  echo "▶ Rodando spy do nicho: $nicho" | tee -a "$LOG_FILE"

  # Prompt pra o Claude Code com a skill spy-wolf
  PROMPT="Use a skill spy-wolf para fazer spy do nicho com id '$nicho'. Quando terminar de coletar os domínios confirmados, envie o resultado via webhook para o Axcend chamando:

POST $AXCEND_URL
Authorization: Bearer $AXCEND_TOKEN
Content-Type: application/json
Body: {
  \"nichoId\": \"$nicho\",
  \"broadcast\": true,
  \"dominios\": [array com {host, volume, copy, advertisers}]
}

Faça o POST com curl ou fetch no final. Apenas envie domínios CONFIRMADOS (que passaram pela verificação de copy). Não envie TENTATIVOS nem DESCARTADOS."

  # Roda Claude Code em print mode (-p) com timeout 15min
  if timeout 900 claude -p "$PROMPT" 2>&1 | tee -a "$LOG_FILE"; then
    SUCESSO=$((SUCESSO + 1))
    echo "✅ $nicho concluído" | tee -a "$LOG_FILE"
  else
    FALHAS=$((FALHAS + 1))
    echo "❌ $nicho falhou (timeout ou erro)" | tee -a "$LOG_FILE"
  fi

  # Pausa 30s entre nichos pra não atropelar
  sleep 30
done

echo "" | tee -a "$LOG_FILE"
echo "═══════════════════════════════════════════════════" | tee -a "$LOG_FILE"
echo "📊 Resumo: $SUCESSO/$TOTAL sucesso · $FALHAS falhas" | tee -a "$LOG_FILE"
echo "═══════════════════════════════════════════════════" | tee -a "$LOG_FILE"
