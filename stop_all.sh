#!/bin/bash

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${YELLOW}🛑 STOPPING MATRISKS SERVICES${NC}"
echo "========================================="

# Stop all uvicorn and vite processes
echo -e "${BLUE}Stopping backend services...${NC}"
pkill -f "uvicorn.*app.main:app"
pkill -f "uvicorn.*routes:app"

echo -e "${BLUE}Stopping frontend service...${NC}"
pkill -f "vite"

sleep 2

# Verify all stopped
REMAINING=$(ps aux | grep -E "uvicorn|vite" | grep -v grep | wc -l)

if [ $REMAINING -eq 0 ]; then
    echo -e "${GREEN}✅ All services stopped successfully!${NC}"
else
    echo -e "${YELLOW}⚠️  Some processes may still be running. Trying force kill...${NC}"
    pkill -9 -f "uvicorn"
    pkill -9 -f "vite"
    sleep 1
    
    REMAINING=$(ps aux | grep -E "uvicorn|vite" | grep -v grep | wc -l)
    if [ $REMAINING -eq 0 ]; then
        echo -e "${GREEN}✅ All services force stopped!${NC}"
    else
        echo -e "${RED}❌ Some processes could not be stopped. Check manually:${NC}"
        ps aux | grep -E "uvicorn|vite" | grep -v grep
    fi
fi

echo ""
echo -e "${BLUE}To start services again, run:${NC}"
echo -e "   ${GREEN}./start_all.sh${NC}"
