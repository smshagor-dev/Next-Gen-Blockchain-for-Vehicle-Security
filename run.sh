#!/bin/bash
# OmniGuard V2X: A Privacy-Preserving Blockchain Framework for Smart Vehicle Security
# Developer : Md Shahanur Islam Shagor
# Role      : Project Architect & Lead Developer
# SmartCar System - Build & Run Script
# Builds C++ core and runs all components

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$SCRIPT_DIR"
BUILD_DIR="$PROJECT_DIR/build"

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

print_header() {
    echo -e "${CYAN}"
    echo "â•”â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•—"
    echo "â•‘   SmartCar Blockchain Security System        â•‘"
    echo "â•‘   SHA2 + SHA3 | Dual Hash | E2E Encrypted   â•‘"
    echo "â•šâ•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•"
    echo -e "${NC}"
}

check_deps() {
    echo -e "${YELLOW}[*] Checking dependencies...${NC}"
    local missing=()
    command -v python3 >/dev/null || missing+=("python3")
    command -v pip3 >/dev/null || command -v pip >/dev/null || missing+=("pip")
    
    if [ ${#missing[@]} -gt 0 ]; then
        echo -e "${RED}[!] Missing: ${missing[*]}${NC}"
        exit 1
    fi
    echo -e "${GREEN}[âœ“] All dependencies found${NC}"
}

install_python_deps() {
    echo -e "${YELLOW}[*] Installing Python dependencies...${NC}"
    pip3 install --quiet --break-system-packages 2>/dev/null || true
    echo -e "${GREEN}[âœ“] Python ready (using stdlib only)${NC}"
}

build_cpp() {
    echo -e "${YELLOW}[*] Building C++ blockchain core...${NC}"
    mkdir -p "$BUILD_DIR"
    
    # Check if nlohmann/json is available
    if command -v g++ >/dev/null 2>&1; then
        # Try to compile (may fail if nlohmann not installed - that's ok)
        g++ -std=c++17 -O2 -Wall \
            "$PROJECT_DIR/blockchain.cpp" \
            -o "$BUILD_DIR/smartcar_blockchain" \
            2>/dev/null && \
            echo -e "${GREEN}[âœ“] C++ core built: $BUILD_DIR/smartcar_blockchain${NC}" || \
            echo -e "${YELLOW}[~] C++ build skipped (nlohmann/json not found - Python mode)${NC}"
    else
        echo -e "${YELLOW}[~] g++ not found, using Python mode${NC}"
    fi
}

build_camera_cpp() {
    echo -e "${YELLOW}[*] Building C++ camera emergency brake module...${NC}"
    mkdir -p "$BUILD_DIR"
    if command -v g++ >/dev/null 2>&1 && command -v pkg-config >/dev/null 2>&1; then
        if pkg-config --exists opencv4; then
            g++ -std=c++17 -O2 -Wall \
                "$PROJECT_DIR/camera_emergency_brake.cpp" \
                -o "$BUILD_DIR/camera_emergency_brake" \
                $(pkg-config --cflags --libs opencv4) && \
                echo -e "${GREEN}[âœ“] Camera module built: $BUILD_DIR/camera_emergency_brake${NC}" || \
                echo -e "${RED}[!] Camera module build failed${NC}"
        else
            echo -e "${YELLOW}[~] OpenCV (opencv4) not found via pkg-config${NC}"
        fi
    else
        echo -e "${YELLOW}[~] g++ or pkg-config not found${NC}"
    fi
}

run_camera_cpp() {
    build_camera_cpp
    if [ -f "$BUILD_DIR/camera_emergency_brake" ]; then
        echo -e "${CYAN}[i] Starting camera emergency brake (press q to quit)${NC}"
        "$BUILD_DIR/camera_emergency_brake" "${2:-0}" "${3:-8.0}"
    else
        echo -e "${RED}[!] Camera executable not available${NC}"
        exit 1
    fi
}

create_logs_dir() {
    mkdir -p "$PROJECT_DIR/logs"
    echo -e "${GREEN}[âœ“] Logs directory ready${NC}"
}

run_python_core_test() {
    echo -e "${YELLOW}[*] Running Python blockchain core test...${NC}"
    cd "$PROJECT_DIR"
    python3 blockchain.py
    echo -e "${GREEN}[âœ“] Python core test complete${NC}"
}

run_sensor_test() {
    echo -e "${YELLOW}[*] Running sensor simulation test...${NC}"
    cd "$PROJECT_DIR"
    python3 vehicle_sensors.py
    echo -e "${GREEN}[âœ“] Sensor test complete${NC}"
}

run_gui() {
    echo -e "${YELLOW}[*] Launching SmartCar Dashboard GUI...${NC}"
    echo -e "${CYAN}[i] Auth Token: SECURE_AUTH_TOKEN_SHA3_2024${NC}"
    echo -e "${CYAN}[i] Default token is pre-filled in the GUI${NC}"
    cd "$PROJECT_DIR"
    python3 dashboard.py
}

show_usage() {
    echo "Usage: $0 [command]"
    echo ""
    echo "Commands:"
    echo "  all       - Build and run everything (default)"
    echo "  build     - Build C++ core only"
    echo "  gui       - Launch GUI dashboard"
    echo "  test      - Run Python core tests"
    echo "  sensors   - Run sensor simulation test"
    echo "  camera    - Build and run C++ camera emergency brake module"
    echo "  clean     - Clean build artifacts"
    echo "  help      - Show this help"
}

clean() {
    echo -e "${YELLOW}[*] Cleaning build artifacts...${NC}"
    rm -rf "$BUILD_DIR"
    rm -f "$PROJECT_DIR/logs/"*.json
    echo -e "${GREEN}[âœ“] Cleaned${NC}"
}

# Main
print_header
check_deps

case "${1:-all}" in
    all)
        create_logs_dir
        install_python_deps
        build_cpp
        run_gui
        ;;
    build)
        build_cpp
        ;;
    gui)
        create_logs_dir
        run_gui
        ;;
    test)
        create_logs_dir
        run_python_core_test
        ;;
    sensors)
        run_sensor_test
        ;;
    camera)
        run_camera_cpp "$@"
        ;;
    clean)
        clean
        ;;
    help|--help|-h)
        show_usage
        ;;
    *)
        echo -e "${RED}Unknown command: $1${NC}"
        show_usage
        exit 1
        ;;
esac

