#!/bin/bash

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

PROJECT_ROOT="/home/mhy/matrisks"
BACKEND_DIR="$PROJECT_ROOT/matrisks-backend"
FRONTEND_DIR="$PROJECT_ROOT/matrisks-frontend"
VENV_PATH="$BACKEND_DIR/venv"
LOG_DIR="$PROJECT_ROOT/logs"

# Create logs directory
mkdir -p "$LOG_DIR"

echo -e "${BLUE}🚀 STARTING MATRISKS FULL STACK${NC}"
echo "========================================="

# Kill any existing processes
echo -e "${YELLOW}🧹 Cleaning up existing processes...${NC}"
pkill -f "uvicorn.*app.main:app" >/dev/null 2>&1
pkill -f "uvicorn.*routes:app" >/dev/null 2>&1
pkill -f "vite" >/dev/null 2>&1
sleep 2

# Check if virtual environment exists
if [ ! -d "$VENV_PATH" ]; then
    echo -e "${RED}❌ Virtual environment not found at $VENV_PATH${NC}"
    echo -e "${YELLOW}Please run setup.sh first to set up the environment${NC}"
    exit 1
fi

# Activate virtual environment
echo -e "${BLUE}🔧 Activating virtual environment...${NC}"
source "$VENV_PATH/bin/activate"

# Set PYTHONPATH to include both backend and AI module
export PYTHONPATH="$BACKEND_DIR:$PROJECT_ROOT:$PYTHONPATH"

# Start main backend server
echo -e "${GREEN}🚀 Starting Main Backend API (port 8000)...${NC}"
cd "$BACKEND_DIR"
nohup uvicorn app.main:app --reload --host 0.0.0.0 --port 8000 > "$LOG_DIR/backend.log" 2>&1 &
BACKEND_PID=$!
echo -e "${BLUE}   Backend PID: $BACKEND_PID${NC}"
echo -e "${BLUE}   Log file: $LOG_DIR/backend.log${NC}"

# Wait for backend to initialize
sleep 5

# Start AI-based malware detection module
echo -e "${GREEN}🤖 Starting AI Malware Detection Service (port 8001)...${NC}"
cd "$PROJECT_ROOT/ai_based_malware_detection"
nohup uvicorn routes:app --reload --host 0.0.0.0 --port 8001 > "$LOG_DIR/ai_module.log" 2>&1 &
AI_PID=$!
echo -e "${BLUE}   AI Module PID: $AI_PID${NC}"
echo -e "${BLUE}   Log file: $LOG_DIR/ai_module.log${NC}"

# Wait for AI service to initialize
sleep 5

# Start frontend
echo -e "${GREEN}🎨 Starting Frontend Development Server (port 5173)...${NC}"
cd "$FRONTEND_DIR"
nohup npm run dev > "$LOG_DIR/frontend.log" 2>&1 &
FRONTEND_PID=$!
echo -e "${BLUE}   Frontend PID: $FRONTEND_PID${NC}"
echo -e "${BLUE}   Log file: $LOG_DIR/frontend.log${NC}"

# Wait for all services to start
sleep 8

echo ""
echo -e "${GREEN}✅ ALL SERVICES STARTED!${NC}"
echo "========================================="
echo ""
echo -e "${BLUE}🌐 Service URLs:${NC}"
echo -e "   🔗 Main Backend:     ${GREEN}http://localhost:8000${NC}"
echo -e "      API Docs:         ${GREEN}http://localhost:8000/docs${NC}"
echo -e "   🤖 AI Detection:     ${GREEN}http://localhost:8001${NC}"
echo -e "      AI API Docs:      ${GREEN}http://localhost:8001/docs${NC}"
echo -e "      AI Health:        ${GREEN}http://localhost:8001/ai_detection/health${NC}"
echo -e "   🎨 Frontend:         ${GREEN}http://localhost:5173${NC}"
echo ""
echo -e "${BLUE}📊 Static Analysis Tools (Available):${NC}"
echo -e "   📁 Basic Static:     ${YELLOW}$PROJECT_ROOT/matrisksBasicStatic${NC}"
echo -e "   📁 Advanced Static:  ${YELLOW}$PROJECT_ROOT/matrisksAdvanceStatic${NC}"
echo -e "   Usage: ${YELLOW}cd <tool-dir> && python matrisks.py <apk-file>${NC}"
echo ""
echo -e "${BLUE}📝 Process IDs:${NC}"
echo -e "   Backend:  $BACKEND_PID"
echo -e "   AI:       $AI_PID"
echo -e "   Frontend: $FRONTEND_PID"
echo ""
echo -e "${BLUE}📋 Log Files:${NC}"
echo -e "   Backend:  $LOG_DIR/backend.log"
echo -e "   AI:       $LOG_DIR/ai_module.log"
echo -e "   Frontend: $LOG_DIR/frontend.log"
echo ""
echo -e "${YELLOW}⚠️  To stop all servers, run:${NC}"
echo -e "   ${RED}./stop_all.sh${NC}"
echo -e "   or manually: ${RED}pkill -f 'uvicorn|vite'${NC}"
echo ""
echo -e "${GREEN}💡 Ready to use! Open http://localhost:5173 in your browser${NC}"
echo ""
echo -e "${BLUE}📊 To view logs in real-time:${NC}"
echo -e "   tail -f $LOG_DIR/backend.log"
echo -e "   tail -f $LOG_DIR/ai_module.log"
echo -e "   tail -f $LOG_DIR/frontend.log"
echo ""

# Verify services are running
sleep 2
echo -e "${BLUE}🔍 Verifying services...${NC}"
if curl -s http://localhost:8000/health > /dev/null; then
    echo -e "${GREEN}   ✓ Backend is responding${NC}"
else
    echo -e "${RED}   ✗ Backend not responding (check logs)${NC}"
fi

if curl -s http://localhost:8001/ai_detection/health > /dev/null; then
    echo -e "${GREEN}   ✓ AI Module is responding${NC}"
else
    echo -e "${RED}   ✗ AI Module not responding (check logs)${NC}"
fi

if curl -s http://localhost:5173 > /dev/null; then
    echo -e "${GREEN}   ✓ Frontend is responding${NC}"
else
    echo -e "${RED}   ✗ Frontend not responding (check logs)${NC}"
fi

echo ""
echo -e "${GREEN}✅ Startup complete!${NC}"
