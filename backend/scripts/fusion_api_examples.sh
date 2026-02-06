#!/bin/bash
# ==============================================================================
# AI_MODULE: Fusion API Examples
# AI_DESCRIPTION: Esempi curl per testare Fusion API
# AI_BUSINESS: Quick reference per sviluppatori
# AI_TEACHING: curl, REST API testing, jq JSON parsing
# ==============================================================================

# Configuration
BASE_URL="${FUSION_API_URL:-http://localhost:8000}"
TOKEN="${AUTH_TOKEN:-YOUR_JWT_TOKEN_HERE}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo "=========================================="
echo -e "${BLUE}FUSION API EXAMPLES${NC}"
echo "=========================================="
echo "Base URL: $BASE_URL"
echo ""

# ==============================================================================
# PUBLIC ENDPOINTS (No Auth)
# ==============================================================================

echo -e "${YELLOW}=== PUBLIC ENDPOINTS (No Auth) ===${NC}"
echo ""

# 1. Health Check
echo -e "${GREEN}1. Health Check${NC}"
echo "curl $BASE_URL/api/v1/fusion/health"
curl -s "$BASE_URL/api/v1/fusion/health" | python -m json.tool 2>/dev/null || curl -s "$BASE_URL/api/v1/fusion/health"
echo ""
echo ""

# 2. Get Styles
echo -e "${GREEN}2. Get Available Styles${NC}"
echo "curl $BASE_URL/api/v1/fusion/styles"
curl -s "$BASE_URL/api/v1/fusion/styles" | python -m json.tool 2>/dev/null || curl -s "$BASE_URL/api/v1/fusion/styles"
echo ""
echo ""

# 3. Get Presets
echo -e "${GREEN}3. Get Configuration Presets${NC}"
echo "curl $BASE_URL/api/v1/fusion/presets"
curl -s "$BASE_URL/api/v1/fusion/presets" | python -m json.tool 2>/dev/null || curl -s "$BASE_URL/api/v1/fusion/presets"
echo ""
echo ""

# ==============================================================================
# AUTHENTICATED ENDPOINTS
# ==============================================================================

echo -e "${YELLOW}=== AUTHENTICATED ENDPOINTS ===${NC}"
echo ""

if [ "$TOKEN" = "YOUR_JWT_TOKEN_HERE" ]; then
    echo -e "${RED}WARNING: No auth token set.${NC}"
    echo "Set AUTH_TOKEN environment variable or edit this script."
    echo ""
    echo "Example:"
    echo "  export AUTH_TOKEN=eyJhbG..."
    echo "  ./fusion_api_examples.sh"
    echo ""
    echo "Skipping authenticated endpoints..."
    exit 0
fi

# 4. List Projects
echo -e "${GREEN}4. List My Projects${NC}"
echo "curl -H 'Authorization: Bearer \$TOKEN' $BASE_URL/api/v1/fusion/projects"
curl -s -H "Authorization: Bearer $TOKEN" "$BASE_URL/api/v1/fusion/projects" | python -m json.tool 2>/dev/null
echo ""
echo ""

# 5. Create Project
echo -e "${GREEN}5. Create New Project${NC}"
PROJECT_NAME="Test Project $(date +%s)"
echo "curl -X POST -H 'Authorization: Bearer \$TOKEN' -H 'Content-Type: application/json' \\"
echo "     -d '{\"name\":\"$PROJECT_NAME\",\"style\":\"karate\"}' \\"
echo "     $BASE_URL/api/v1/fusion/projects"

CREATE_RESPONSE=$(curl -s -X POST \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"name\":\"$PROJECT_NAME\",\"style\":\"karate\",\"description\":\"Test project for API examples\"}" \
    "$BASE_URL/api/v1/fusion/projects")

echo "$CREATE_RESPONSE" | python -m json.tool 2>/dev/null || echo "$CREATE_RESPONSE"
echo ""

# Extract project ID for further tests
PROJECT_ID=$(echo "$CREATE_RESPONSE" | python -c "import sys,json; print(json.load(sys.stdin).get('id',''))" 2>/dev/null)

if [ -n "$PROJECT_ID" ] && [ "$PROJECT_ID" != "" ]; then
    echo -e "${GREEN}Created project ID: $PROJECT_ID${NC}"
    echo ""

    # 6. Get Project Detail
    echo -e "${GREEN}6. Get Project Detail${NC}"
    echo "curl -H 'Authorization: Bearer \$TOKEN' $BASE_URL/api/v1/fusion/projects/$PROJECT_ID"
    curl -s -H "Authorization: Bearer $TOKEN" "$BASE_URL/api/v1/fusion/projects/$PROJECT_ID" | python -m json.tool 2>/dev/null
    echo ""
    echo ""

    # 7. Update Project
    echo -e "${GREEN}7. Update Project${NC}"
    echo "curl -X PUT -H 'Authorization: Bearer \$TOKEN' -H 'Content-Type: application/json' \\"
    echo "     -d '{\"description\":\"Updated description\"}' \\"
    echo "     $BASE_URL/api/v1/fusion/projects/$PROJECT_ID"
    curl -s -X PUT \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d '{"description":"Updated description via API examples"}' \
        "$BASE_URL/api/v1/fusion/projects/$PROJECT_ID" | python -m json.tool 2>/dev/null
    echo ""
    echo ""

    # 8. Get Project Status
    echo -e "${GREEN}8. Get Processing Status${NC}"
    echo "curl -H 'Authorization: Bearer \$TOKEN' $BASE_URL/api/v1/fusion/projects/$PROJECT_ID/status"
    curl -s -H "Authorization: Bearer $TOKEN" "$BASE_URL/api/v1/fusion/projects/$PROJECT_ID/status" | python -m json.tool 2>/dev/null
    echo ""
    echo ""

    # 9. Delete Project (Cleanup)
    echo -e "${GREEN}9. Delete Project (Cleanup)${NC}"
    echo "curl -X DELETE -H 'Authorization: Bearer \$TOKEN' $BASE_URL/api/v1/fusion/projects/$PROJECT_ID"
    DELETE_RESPONSE=$(curl -s -X DELETE -H "Authorization: Bearer $TOKEN" "$BASE_URL/api/v1/fusion/projects/$PROJECT_ID")
    echo "Response: $DELETE_RESPONSE"
    echo ""
else
    echo -e "${RED}Could not extract project ID from create response${NC}"
fi

echo ""
echo "=========================================="
echo -e "${GREEN}Examples completed${NC}"
echo "=========================================="
