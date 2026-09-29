#!/usr/bin/env bash
# ==============================================================================
# ARMSS Gateway API Test Script (Ubuntu / Linux Bash)
# ==============================================================================
# Usage:
#   chmod +x test_auth_api.sh
#   ./test_auth_api.sh [identifier] [password] [base_url]
#
# Examples:
#   ./test_auth_api.sh
#   ./test_auth_api.sh admin secret123
#   ./test_auth_api.sh admin secret123 https://armssgateway.arminfo.in
# ==============================================================================

BASE_URL="${3:-http://localhost:2092}"
IDENTIFIER="${1:-admin}"
PASSWORD="${2:-password123}"

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}====================================================${NC}"
echo -e "${BLUE}  ARMSS Gateway Auth API Test Suite                 ${NC}"
echo -e "${BLUE}====================================================${NC}"
echo -e "Target URL : ${YELLOW}${BASE_URL}${NC}"
echo -e "Identifier : ${YELLOW}${IDENTIFIER}${NC}"
echo -e "Password   : ${YELLOW}********${NC}"
echo -e "----------------------------------------------------"

# ------------------------------------------------------------------------------
# 1. Health Check
# ------------------------------------------------------------------------------
echo -e "\n${BLUE}[1/4] Testing Health Endpoint (GET /api/v1/health)...${NC}"
HEALTH_RESP=$(curl -s -w "\n%{http_code}" "${BASE_URL}/api/v1/health")
HEALTH_CODE=$(echo "$HEALTH_RESP" | tail -n1)
HEALTH_BODY=$(echo "$HEALTH_RESP" | sed '$d')

if [ "$HEALTH_CODE" = "200" ]; then
  echo -e "${GREEN}✓ Health Check Passed (HTTP 200)${NC}"
  echo "$HEALTH_BODY"
else
  echo -e "${RED}✗ Health Check Failed (HTTP ${HEALTH_CODE})${NC}"
  echo "$HEALTH_BODY"
fi

# ------------------------------------------------------------------------------
# 2. Portal User Login
# ------------------------------------------------------------------------------
echo -e "\n${BLUE}[2/4] Testing Portal Login (POST /api/v1/portal/login)...${NC}"
LOGIN_PAYLOAD=$(cat <<EOF
{
  "identifier": "${IDENTIFIER}",
  "password": "${PASSWORD}"
}
EOF
)

LOGIN_RESP=$(curl -s -w "\n%{http_code}" -X POST "${BASE_URL}/api/v1/portal/login" \
  -H "Content-Type: application/json" \
  -d "$LOGIN_PAYLOAD")

LOGIN_CODE=$(echo "$LOGIN_RESP" | tail -n1)
LOGIN_BODY=$(echo "$LOGIN_RESP" | sed '$d')

echo -e "HTTP Status: ${YELLOW}${LOGIN_CODE}${NC}"
echo "$LOGIN_BODY"

# Extract token if jq or grep/sed is available
TOKEN=$(echo "$LOGIN_BODY" | grep -o '"token":"[^"]*' | cut -d'"' -f4)

# ------------------------------------------------------------------------------
# 3. Authenticated Profile Verification
# ------------------------------------------------------------------------------
echo -e "\n${BLUE}[3/4] Testing Protected Profile (GET /api/v1/portal/me)...${NC}"
if [ -n "$TOKEN" ]; then
  echo -e "${GREEN}Found JWT Token:${NC} ${TOKEN:0:25}..."
  ME_RESP=$(curl -s -w "\n%{http_code}" -X GET "${BASE_URL}/api/v1/portal/me" \
    -H "Authorization: Bearer ${TOKEN}")
  
  ME_CODE=$(echo "$ME_RESP" | tail -n1)
  ME_BODY=$(echo "$ME_RESP" | sed '$d')
  
  echo -e "HTTP Status: ${YELLOW}${ME_CODE}${NC}"
  echo "$ME_BODY"
else
  echo -e "${YELLOW}Skipping /portal/me (Login did not return a token. Verify credentials.)${NC}"
fi

# ------------------------------------------------------------------------------
# 4. Device Client Password Verification
# ------------------------------------------------------------------------------
echo -e "\n${BLUE}[4/4] Testing Device Auth (POST /api/v1/auth/verify-password)...${NC}"
VERIFY_RESP=$(curl -s -w "\n%{http_code}" -X POST "${BASE_URL}/api/v1/auth/verify-password" \
  -H "Content-Type: application/json" \
  -d "$LOGIN_PAYLOAD")

VERIFY_CODE=$(echo "$VERIFY_RESP" | tail -n1)
VERIFY_BODY=$(echo "$VERIFY_RESP" | sed '$d')

echo -e "HTTP Status: ${YELLOW}${VERIFY_CODE}${NC}"
echo "$VERIFY_BODY"

echo -e "\n${BLUE}====================================================${NC}"
echo -e "${GREEN}Tests Completed!${NC}"
echo -e "${BLUE}====================================================${NC}"
