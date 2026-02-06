#!/bin/bash

# Enterprise Test Suite Runner
# Target: 90%+ coverage, 95%+ pass rate

set -e

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║           Enterprise Test Suite - Flutter App                 ║"
echo "║                  Target: 90%+ Coverage, 95%+ Pass Rate       ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Parse arguments
RUN_UNIT=false
RUN_INTEGRATION=false
RUN_REGRESSION=false
RUN_SECURITY=false
RUN_PENETRATION=false
RUN_SLOW=false
RUN_COVERAGE=false
GENERATE_REPORT=false

if [ $# -eq 0 ]; then
    RUN_UNIT=true
    RUN_INTEGRATION=true
    RUN_REGRESSION=true
    RUN_SECURITY=true
fi

for arg in "$@"; do
    case $arg in
        --all)
            RUN_UNIT=true
            RUN_INTEGRATION=true
            RUN_REGRESSION=true
            RUN_SECURITY=true
            RUN_PENETRATION=true
            RUN_SLOW=true
            ;;
        --unit) RUN_UNIT=true ;;
        --integration) RUN_INTEGRATION=true ;;
        --regression) RUN_REGRESSION=true ;;
        --security) RUN_SECURITY=true ;;
        --penetration) RUN_PENETRATION=true ;;
        --slow) RUN_SLOW=true ;;
        --coverage) RUN_COVERAGE=true ;;
        --report) GENERATE_REPORT=true ;;
    esac
done

# Function to run tests with a specific tag
run_tests_by_tag() {
    local tag=$1
    local name=$2

    echo ""
    echo -e "${BLUE}▶ Running $name...${NC}"
    flutter test --tags=$tag --reporter=expanded
    echo -e "${GREEN}✓ $name completed${NC}"
}

# Run test categories
if [ "$RUN_UNIT" = true ]; then
    run_tests_by_tag "unit" "Unit Tests"
fi

if [ "$RUN_INTEGRATION" = true ]; then
    run_tests_by_tag "integration" "Integration Tests"
fi

if [ "$RUN_REGRESSION" = true ]; then
    run_tests_by_tag "regression" "Regression Tests"
fi

if [ "$RUN_SECURITY" = true ]; then
    run_tests_by_tag "security" "Security Tests"
fi

if [ "$RUN_PENETRATION" = true ]; then
    run_tests_by_tag "penetration" "Penetration Tests"
fi

if [ "$RUN_SLOW" = true ]; then
    run_tests_by_tag "slow" "Slow Tests (Performance, Holistic)"
fi

# Generate coverage report
if [ "$RUN_COVERAGE" = true ]; then
    echo ""
    echo -e "${BLUE}▶ Generating Coverage Report...${NC}"
    flutter test --coverage

    # Check if lcov is installed
    if command -v lcov &> /dev/null && command -v genhtml &> /dev/null; then
        lcov --remove coverage/lcov.info 'lib/generated/*' 'lib/**/*.g.dart' 'lib/**/*.freezed.dart' -o coverage/lcov.info
        genhtml coverage/lcov.info -o coverage/html
        echo -e "${GREEN}✓ Coverage report generated at coverage/html/index.html${NC}"
    else
        echo -e "${YELLOW}⚠ lcov/genhtml not installed. Install with: brew install lcov${NC}"
    fi

    # Parse coverage percentage
    if [ -f coverage/lcov.info ]; then
        COVERAGE=$(lcov --summary coverage/lcov.info 2>&1 | grep "lines" | grep -oP '\d+\.\d+')
        echo ""
        echo "═══════════════════════════════════════════════════════════════"
        if (( $(echo "$COVERAGE >= 90" | bc -l) )); then
            echo -e "${GREEN}✓ Coverage: ${COVERAGE}% (Target: 90%) - PASS${NC}"
        else
            echo -e "${RED}✗ Coverage: ${COVERAGE}% (Target: 90%) - FAIL${NC}"
        fi
        echo "═══════════════════════════════════════════════════════════════"
    fi
fi

# Generate test report
if [ "$GENERATE_REPORT" = true ]; then
    echo ""
    echo -e "${BLUE}▶ Generating Test Report...${NC}"

    TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")
    REPORT_FILE="test_report_$(date +%Y%m%d_%H%M%S).txt"

    cat > "$REPORT_FILE" << EOF
═══════════════════════════════════════════════════════════════════════════════
                         ENTERPRISE TEST REPORT
                         Generated: $TIMESTAMP
═══════════════════════════════════════════════════════════════════════════════

Run flutter test for detailed results.

Test Categories Executed:
- Unit Tests: $RUN_UNIT
- Integration Tests: $RUN_INTEGRATION
- Regression Tests: $RUN_REGRESSION
- Security Tests: $RUN_SECURITY
- Penetration Tests: $RUN_PENETRATION
- Slow Tests: $RUN_SLOW

Coverage Report: $RUN_COVERAGE

EOF

    echo -e "${GREEN}✓ Report saved to $REPORT_FILE${NC}"
fi

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "                     Test Run Complete                          "
echo "═══════════════════════════════════════════════════════════════"
