#!/bin/bash

echo "🚀 STARTING MATRISKS SERVERS"
echo "============================"

# Kill any existing processes
echo "🧹 Cleaning up existing processes..."
pkill -f "uvicorn.*app.main:app" >/dev/null 2>&1
pkill -f "vite" >/dev/null 2>&1
sleep 2

# Start backend
echo "🔧 Starting backend server..."
cd /home/zain/matrisks/matrisks-backend
PYTHONPATH=/home/zain/matrisks/matrisks-backend /home/zain/matrisks/venv/bin/python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000 &
BACKEND_PID=$!

# Wait for backend
sleep 5

# Start frontend
echo "🎨 Starting frontend server..."
cd /home/zain/matrisks/matrisks-frontend
npm run dev &
FRONTEND_PID=$!

# Wait for both to start
sleep 5

echo ""
echo "✅ SERVERS READY!"
echo "================="
echo "🔗 Backend:  http://localhost:8000"
echo "🎨 Frontend: http://localhost:5173"
echo ""
echo "📝 Process IDs:"
echo "   Backend:  $BACKEND_PID"
echo "   Frontend: $FRONTEND_PID"
echo ""
echo "⚠️  To stop servers: pkill -f 'uvicorn\\|vite'"
echo "💡 Registration should now work at http://localhost:5173"

# Keep script running to monitor
wait