#!/bin/bash

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${YELLOW}STOPPING MATRISKS SERVICES${NC}"
echo -e "${YELLOW}This will shut down all running components${NC}"
echo "========================================="

# Stop all uvicorn and vite processes
echo -e "${BLUE}[STOPPING] Backend API servers...${NC}"
echo "   Terminating main backend (port 8000) and AI module (port 8001)"
pkill -f "uvicorn.*app.main:app"
pkill -f "uvicorn.*routes:app"

echo -e "${BLUE}[STOPPING] Frontend web server...${NC}"
echo "   Terminating React development server (port 5173)"
pkill -f "vite"

# Stop any running Android emulators (Dynamic Analyzer)
echo -e "${BLUE}[STOPPING] Android emulators (if running)...${NC}"
echo "   Checking for active emulator instances used by Dynamic Analyzer"
if command -v adb >/dev/null 2>&1; then
    adb devices | grep emulator | cut -f1 | while read emulator; do
        echo -e "${YELLOW}   Terminating emulator: $emulator${NC}"
        adb -s "$emulator" emu kill >/dev/null 2>&1
    done
fi
pkill -f "qemu-system" >/dev/null 2>&1
pkill -f "emulator.*-avd" >/dev/null 2>&1

sleep 2

# Verify all stopped
REMAINING=$(ps aux | grep -E "uvicorn|vite|qemu-system|emulator.*-avd" | grep -v grep | wc -l)

if [ $REMAINING -eq 0 ]; then
    echo -e "${GREEN}[SUCCESS] All services stopped successfully!${NC}"
else
    echo -e "${YELLOW}[WARNING] Some processes are still running. Attempting force termination...${NC}"
    echo "   Using SIGKILL (-9) to forcefully stop remaining processes"
    pkill -9 -f "uvicorn"
    pkill -9 -f "vite"
    pkill -9 -f "qemu-system"
    pkill -9 -f "emulator"
    sleep 1
    
    REMAINING=$(ps aux | grep -E "uvicorn|vite|qemu-system|emulator.*-avd" | grep -v grep | wc -l)
    if [ $REMAINING -eq 0 ]; then
        echo -e "${GREEN}[SUCCESS] All services force stopped successfully!${NC}"
    else
        echo -e "${RED}[ERROR] Some processes could not be stopped.${NC}"
        echo -e "${RED}You may need to manually terminate these processes:${NC}"
        echo ""
        ps aux | grep -E "uvicorn|vite|qemu-system|emulator" | grep -v grep
    fi
fi

echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}TO RESTART ALL SERVICES:${NC}"
echo -e "   Run: ${GREEN}./start_all.sh${NC}"
echo -e "${BLUE}========================================${NC}"
