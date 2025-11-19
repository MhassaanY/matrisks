#!/bin/bash

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

PROJECT_ROOT="$(cd "$(dirname "$0")" && pwd)"
BACKEND_DIR="$PROJECT_ROOT/matrisks-backend"
FRONTEND_DIR="$PROJECT_ROOT/matrisks-frontend"
DYNAMIC_DIR="$PROJECT_ROOT/matrisksDynamicAnalyzer"
AI_DIR="$PROJECT_ROOT/ai_based_malware_detection"
VENV_PATH="$BACKEND_DIR/venv"
LOG_DIR="$PROJECT_ROOT/logs"

# Create logs directory
mkdir -p "$LOG_DIR"

echo -e "${BLUE}STARTING MATRISKS FULL STACK${NC}"
echo -e "${BLUE}This will launch all security analysis services${NC}"
echo "========================================="
echo ""
echo -e "${BLUE}[INFO] System Requirements:${NC}"
echo "   - Backend API: Python 3.8+, PostgreSQL database"
echo "   - AI Module: Machine learning libraries (scikit-learn, pandas)"
echo "   - Frontend: Node.js 16+ with npm"
echo "   - Static Analyzers: Androguard, weasyprint dependencies"
echo "   - Dynamic Analyzer: Android SDK, Frida (setup separately)"
echo ""

# Kill any existing processes
echo -e "${YELLOW}[CLEANUP] Stopping any existing MATRISKS processes...${NC}"
echo "   This ensures clean startup without port conflicts"
pkill -f "uvicorn.*app.main:app" >/dev/null 2>&1
pkill -f "uvicorn.*routes:app" >/dev/null 2>&1
pkill -f "vite" >/dev/null 2>&1
sleep 2

# Check if virtual environment exists
if [ ! -d "$VENV_PATH" ]; then
    echo -e "${RED}[ERROR] Virtual environment not found at $VENV_PATH${NC}"
    echo -e "${YELLOW}Please run setup.sh first to install dependencies and configure the environment${NC}"
    exit 1
fi

# Activate virtual environment
echo -e "${BLUE}[SETUP] Activating Python virtual environment...${NC}"
echo "   This loads all installed dependencies for the services"
source "$VENV_PATH/bin/activate"

# Set PYTHONPATH to include both backend and AI module
export PYTHONPATH="$BACKEND_DIR:$PROJECT_ROOT:$PYTHONPATH"

# Start main backend server
echo -e "${GREEN}[STARTING] Main Backend API Server (port 8000)...${NC}"
echo "   This provides the core API for analysis requests and user authentication"
cd "$BACKEND_DIR"
nohup uvicorn app.main:app --reload --host 0.0.0.0 --port 8000 > "$LOG_DIR/backend.log" 2>&1 &
BACKEND_PID=$!
echo -e "${BLUE}   Process ID: $BACKEND_PID${NC}"
echo -e "${BLUE}   Logs: $LOG_DIR/backend.log${NC}"

# Wait for backend to initialize
sleep 5

# Start AI-based malware detection module
echo -e "${GREEN}[STARTING] AI Malware Detection Service (port 8001)...${NC}"
echo "   This runs machine learning models to classify malware threats"
cd "$AI_DIR"
nohup uvicorn routes:app --reload --host 0.0.0.0 --port 8001 > "$LOG_DIR/ai_module.log" 2>&1 &
AI_PID=$!
echo -e "${BLUE}   Process ID: $AI_PID${NC}"
echo -e "${BLUE}   Logs: $LOG_DIR/ai_module.log${NC}"

# Wait for AI service to initialize
sleep 5

# Check Dynamic Analyzer setup (informational, doesn't start a service)
echo -e "${BLUE}[CHECK] Verifying Dynamic Analyzer configuration...${NC}"
echo "   The Dynamic Analyzer runs on-demand when APK analysis is requested"
if [ -d "$DYNAMIC_DIR/venv" ] || [ -L "$DYNAMIC_DIR/venv" ]; then
    if command -v adb >/dev/null 2>&1; then
        echo -e "${GREEN}   [OK] Dynamic Analyzer is configured and ready${NC}"
        echo -e "${BLUE}   Available Android Virtual Devices:${NC}"
        cd "$DYNAMIC_DIR"
        source venv/bin/activate
        python cli.py list-avds 2>/dev/null | head -5 || echo -e "${YELLOW}      (No AVDs configured yet - run setup.py in Dynamic Analyzer directory)${NC}"
        cd "$PROJECT_ROOT"
    else
        echo -e "${YELLOW}   [WARNING] Android SDK tools not found in system PATH${NC}"
        echo -e "${YELLOW}   Dynamic Analyzer requires Android SDK setup. Run:${NC}"
        echo -e "${YELLOW}      cd $DYNAMIC_DIR && python setup.py${NC}"
    fi
else
    echo -e "${YELLOW}   [WARNING] Dynamic Analyzer not set up yet${NC}"
    echo -e "${YELLOW}   To enable runtime APK analysis, run:${NC}"
    echo -e "${YELLOW}      cd $DYNAMIC_DIR && python setup.py${NC}"
fi
sleep 2

# Start frontend
echo -e "${GREEN}[STARTING] Frontend Web Interface (port 5173)...${NC}"
echo "   This provides the React-based user interface for interacting with MATRISKS"
cd "$FRONTEND_DIR"
nohup npm run dev > "$LOG_DIR/frontend.log" 2>&1 &
FRONTEND_PID=$!
echo -e "${BLUE}   Process ID: $FRONTEND_PID${NC}"
echo -e "${BLUE}   Logs: $LOG_DIR/frontend.log${NC}"

# Wait for all services to start
sleep 8

echo ""
echo -e "${GREEN}[SUCCESS] ALL SERVICES STARTED SUCCESSFULLY!${NC}"
echo "========================================="
echo ""
echo -e "${BLUE}SERVICE URLS (click or copy to browser):${NC}"
echo ""
echo -e "   Main Backend API:${NC}"
echo -e "      ${GREEN}http://localhost:8000${NC}"
echo -e "      Interactive API Documentation: ${GREEN}http://localhost:8000/docs${NC}"
echo ""
echo -e "   AI Malware Detection:${NC}"
echo -e "      ${GREEN}http://localhost:8001${NC}"
echo -e "      AI API Documentation: ${GREEN}http://localhost:8001/docs${NC}"
echo -e "      Health Check: ${GREEN}http://localhost:8001/ai_detection/health${NC}"
echo ""
echo -e "   Web Interface (Main Application):${NC}"
echo -e "      ${GREEN}http://localhost:5173${NC}"
echo ""
echo -e "${BLUE}ANALYSIS TOOLS AVAILABLE:${NC}"
echo ""
echo -e "   Basic Static Analysis (fast security scan):${NC}"
echo -e "      Location: ${YELLOW}$PROJECT_ROOT/matrisksBasicStatic${NC}"
echo -e "      Command: ${YELLOW}cd matrisksBasicStatic && python matrisks.py <apk-file>${NC}"
echo ""
echo -e "   Advanced Static Analysis (deep vulnerability scan):${NC}"
echo -e "      Location: ${YELLOW}$PROJECT_ROOT/matrisksAdvanceStatic${NC}"
echo -e "      Command: ${YELLOW}cd matrisksAdvanceStatic && python matrisks.py <apk-file>${NC}"
echo ""
echo -e "   Dynamic Analysis (runtime behavior monitoring):${NC}"
echo -e "      Location: ${YELLOW}$PROJECT_ROOT/matrisksDynamicAnalyzer${NC}"
echo -e "      Command: ${YELLOW}cd matrisksDynamicAnalyzer && python cli.py analyze <apk-file>${NC}"
echo ""
echo -e "   AI Malware Detection (machine learning classification):${NC}"
echo -e "      Endpoint: ${GREEN}http://localhost:8001/ai_detection/predict${NC}"
echo -e "      Usage: POST APK file to endpoint via HTTP client"
echo ""
echo -e "${BLUE}PROCESS INFORMATION:${NC}"
echo ""
echo -e "   Service Process IDs (for monitoring):${NC}"
echo -e "      Backend Server:  $BACKEND_PID"
echo -e "      AI Module:       $AI_PID"
echo -e "      Frontend:        $FRONTEND_PID"
echo ""
echo -e "   Log File Locations (for troubleshooting):${NC}"
echo -e "      Backend:  $LOG_DIR/backend.log"
echo -e "      AI:       $LOG_DIR/ai_module.log"
echo -e "      Frontend: $LOG_DIR/frontend.log"
echo ""
echo -e "${BLUE}HOW TO VIEW LOGS IN REAL-TIME:${NC}"
echo -e "   Backend logs:  tail -f $LOG_DIR/backend.log"
echo -e "   AI logs:       tail -f $LOG_DIR/ai_module.log"
echo -e "   Frontend logs: tail -f $LOG_DIR/frontend.log"
echo ""
echo -e "${YELLOW}TO STOP ALL SERVICES:${NC}"
echo -e "   Run shutdown script: ${RED}./stop_all.sh${NC}"
echo -e "   Or manually: ${RED}pkill -f 'uvicorn|vite'${NC}"
echo ""
echo -e "${GREEN}READY TO USE!${NC}"
echo -e "   Open your web browser and navigate to: ${GREEN}http://localhost:5173${NC}"
echo ""

# Verify services are running
sleep 2
echo -e "${BLUE}[VERIFICATION] Checking if services are responding...${NC}"
echo ""
if curl -s http://localhost:8000/health > /dev/null; then
    echo -e "${GREEN}   [OK] Backend Server is responding on port 8000${NC}"
else
    echo -e "${RED}   [FAILED] Backend not responding - check $LOG_DIR/backend.log for errors${NC}"
fi

if curl -s http://localhost:8001/ai_detection/health > /dev/null; then
    echo -e "${GREEN}   [OK] AI Module is responding on port 8001${NC}"
else
    echo -e "${RED}   [FAILED] AI Module not responding - check $LOG_DIR/ai_module.log for errors${NC}"
fi

if curl -s http://localhost:5173 > /dev/null; then
    echo -e "${GREEN}   [OK] Frontend is responding on port 5173${NC}"
else
    echo -e "${RED}   [FAILED] Frontend not responding - check $LOG_DIR/frontend.log for errors${NC}"
fi

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}[COMPLETE] All startup procedures finished${NC}"
echo -e "${GREEN}========================================${NC}"
