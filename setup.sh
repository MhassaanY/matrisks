#!/usr/bin/env bash
set -euo pipefail

# Root-level setup: creates/uses backend venv and installs all deps from requirements-all.txt

PROJECT_ROOT="$(cd "$(dirname "$0")" && pwd)"
BACKEND_DIR="$PROJECT_ROOT/matrisks-backend"
FRONTEND_DIR="$PROJECT_ROOT/matrisks-frontend"
DYNAMIC_DIR="$PROJECT_ROOT/matrisksDynamicAnalyzer"

echo "========================================"
echo "MATRISKS FRAMEWORK - SETUP SCRIPT"
echo "========================================"
echo ""
echo "[STEP 1/5] Checking system prerequisites..."
echo ""

# Check for required system dependencies
MISSING_DEPS=()

# Check Python 3.8+
if ! command -v python3 &> /dev/null; then
    MISSING_DEPS+=("python3 (3.8 or higher)")
else
    PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
    echo "[OK] Python $PYTHON_VERSION found"
fi

# Check pip
if ! command -v pip3 &> /dev/null && ! python3 -m pip --version &> /dev/null; then
    MISSING_DEPS+=("pip3 (Python package installer)")
else
    echo "[OK] pip found"
fi

# Check Node.js and npm (for frontend)
if ! command -v node &> /dev/null; then
    MISSING_DEPS+=("node (Node.js 16+ for frontend)")
else
    NODE_VERSION=$(node --version)
    echo "[OK] Node.js $NODE_VERSION found"
fi

if ! command -v npm &> /dev/null; then
    MISSING_DEPS+=("npm (Node package manager)")
else
    NPM_VERSION=$(npm --version)
    echo "[OK] npm $NPM_VERSION found"
fi

# Check PostgreSQL
if ! command -v psql &> /dev/null; then
    echo "[WARNING] PostgreSQL client not found in PATH"
    echo "   PostgreSQL database is required for the backend"
    echo "   Install: sudo apt install postgresql postgresql-contrib (Ubuntu/Debian)"
    echo "   or: brew install postgresql (macOS)"
fi

# Check for required system libraries (for weasyprint PDF generation)
if ! ldconfig -p 2>/dev/null | grep -q libpango; then
    echo "[WARNING] libpango not found (required for PDF report generation)"
    echo "   Install: sudo apt install libpango-1.0-0 libpangocairo-1.0-0 (Ubuntu/Debian)"
fi

if ! ldconfig -p 2>/dev/null | grep -q libcairo; then
    echo "[WARNING] libcairo not found (required for PDF report generation)"
    echo "   Install: sudo apt install libcairo2 (Ubuntu/Debian)"
fi

# Report missing critical dependencies
if [ ${#MISSING_DEPS[@]} -gt 0 ]; then
    echo ""
    echo "[ERROR] Missing required dependencies:"
    for dep in "${MISSING_DEPS[@]}"; do
        echo "   - $dep"
    done
    echo ""
    echo "Please install the missing dependencies and run setup.sh again."
    exit 1
fi

echo ""
echo "[STEP 2/5] Creating Python virtual environment..."

python3 -m venv "$BACKEND_DIR/venv"
source "$BACKEND_DIR/venv/bin/activate"

echo ""
echo "[STEP 3/5] Installing Python dependencies..."
echo "   This will install packages from requirements-all.txt"
echo "   Components: Backend, Static Analyzers, Dynamic Analyzer, AI Module"
echo ""

pip install --upgrade pip
pip install -r "$PROJECT_ROOT/requirements-all.txt"

echo ""
echo "[SUCCESS] All Python packages installed"

# Create symlink for Dynamic Analyzer venv (shares backend venv)
if [ ! -L "$DYNAMIC_DIR/venv" ] && [ ! -d "$DYNAMIC_DIR/venv" ]; then
	ln -s "$BACKEND_DIR/venv" "$DYNAMIC_DIR/venv"
	echo "[OK] Created virtual environment symlink for Dynamic Analyzer"
fi

echo ""
echo "[STEP 4/5] Configuring backend environment..."

# Ensure backend .env exists
if [ ! -f "$BACKEND_DIR/.env" ]; then
	if [ -f "$BACKEND_DIR/.env.example" ]; then
		cp "$BACKEND_DIR/.env.example" "$BACKEND_DIR/.env"
		echo "Created $BACKEND_DIR/.env from example. Please review credentials."
	else
		cat > "$BACKEND_DIR/.env" <<EOT
DATABASE_URL=postgresql://postgres:postgres@localhost:5432/matrisks
JWT_SECRET_KEY=change_me
ADMIN_EMAIL=admin@example.com
ADMIN_USERNAME=admin
ADMIN_PASSWORD=admin123
EOT
		echo "Created $BACKEND_DIR/.env (template). Please review credentials."
	fi
fi

echo ""
echo "[STEP 5/5] Running database migrations..."

# Run migrations if alembic is configured
if [ -f "$BACKEND_DIR/alembic.ini" ]; then
	cd "$BACKEND_DIR"
	set +e
	alembic upgrade head
	UPGRADE_STATUS=$?
	set -e
	if [ $UPGRADE_STATUS -ne 0 ]; then
		echo "[WARNING] Alembic upgrade failed (database may already exist)"
		echo "   Attempting to stamp current schema..."
		alembic stamp head
	else
		echo "[SUCCESS] Database migrations applied"
	fi
	cd "$PROJECT_ROOT"
else
	echo "[WARNING] No alembic.ini found, skipping migrations"
fi

cat <<EOF

========================================
SETUP COMPLETED SUCCESSFULLY
========================================

All dependencies have been installed into: $BACKEND_DIR/venv

INSTALLED MODULES:
   - Backend API (FastAPI web server for coordinating analysis)
   - Frontend (React web interface for user interaction)
   - Basic Static Analyzer (fast APK security scanning)
   - Advanced Static Analyzer (deep APK vulnerability analysis)
   - Dynamic Analyzer (runtime behavior monitoring with Frida)
   - AI-Based Malware Detection (machine learning threat detection)

SYSTEM REQUIREMENTS SUMMARY:
   
   Required (already checked):
      - Python 3.8+ with pip
      - Node.js 16+ with npm
      - PostgreSQL database server
   
   Recommended for production:
      - 4GB RAM minimum, 8GB recommended
      - 5GB free disk space
      - Modern Linux/macOS system
   
   Optional (for Dynamic Analyzer):
      - Android SDK command-line tools
      - Android Emulator (API 30, x86_64 system image)
      - Frida 16.1.4
      - KVM support (Linux) or HAXM (macOS) for emulator acceleration

IMPORTANT - DYNAMIC ANALYZER SETUP:
   The Dynamic Analyzer requires Android SDK and Android emulator configuration.
   To complete Dynamic Analyzer setup, run:
      cd $DYNAMIC_DIR && python setup.py
   
   This automated setup will:
      - Download and install Android SDK tools (~100MB)
      - Install Android 11 system image (~800MB)
      - Create optimized AVD (Pixel 5 emulator)
      - Download and configure Frida server (x86_64)
      - Verify installation with test run
   
   Estimated time: 10-15 minutes (depends on internet speed)

PACKAGE DEPENDENCIES INSTALLED:
   
   Backend API (matrisks-backend/requirements.txt):
      - fastapi==0.101.0        (Web framework)
      - uvicorn==0.23.2         (ASGI server)
      - sqlalchemy==2.0.19      (Database ORM)
      - alembic==1.11.3         (Database migrations)
      - psycopg2-binary==2.9.7  (PostgreSQL adapter)
      - pydantic==2.1.1         (Data validation)
      - python-jose==3.3.0      (JWT authentication)
      - passlib==1.7.4          (Password hashing)
      - bcrypt==4.0.1           (Cryptography)
      - python-multipart        (File uploads)
      - scikit-learn>=1.3.0     (Machine learning)
      - numpy>=1.24.0           (Numerical computing)
      - pandas>=2.0.0           (Data analysis)
      - androguard>=3.4.0       (APK analysis)
   
   AI Malware Detection (ai_based_malware_detection/requirements.txt):
      - fastapi>=0.104.0        (API framework)
      - scikit-learn>=1.3.0     (ML models)
      - pandas>=2.0.0           (Data processing)
      - androguard>=3.4.0       (APK parsing)
      - python-magic>=0.4.27    (File type detection)
   
   Basic Static Analyzer (matrisksBasicStatic/requirements.txt):
      - pymongo==3.11.0         (MongoDB driver)
      - androguard>=3.4.0       (APK decompilation)
      - dnspython==2.0.0        (DNS toolkit)
      - weasyprint              (PDF generation)
   
   Advanced Static Analyzer (matrisksAdvanceStatic/requirements.txt):
      - androguard>=4.1.2       (APK analysis)
      - networkx==3.5           (Graph analysis)
      - matplotlib==3.10.6      (Visualization)
      - pydot==4.0.1            (Graph rendering)
      - lxml==6.0.1             (XML processing)
      - PyYAML==6.0.2           (Configuration)
      - weasyprint==66.0        (PDF reports)
   
   Dynamic Analyzer (matrisksDynamicAnalyzer/requirements.txt):
      - frida==16.1.4           (Runtime instrumentation)
      - frida-tools==12.2.1     (Frida CLI tools)
      - androguard>=4.1.2       (APK analysis)
      - pyyaml>=6.0.1           (Configuration)
      - psutil>=5.9.5           (Process monitoring)
      - requests>=2.31.0        (HTTP client)
      - tqdm>=4.66.1            (Progress bars)
      - colorlog>=6.8.0         (Colored logging)
   
   Frontend (matrisks-frontend/package.json):
      - react==19.0.0           (UI framework)
      - react-dom==19.0.0       (DOM rendering)
      - react-router-dom==7.6.0 (Routing)
      - axios==1.9.0            (HTTP client)
      - vite==6.3.1             (Build tool)

NEXT STEPS:

1) Start all services together (recommended for full functionality):
   ./start_all.sh

2) Or start individual components separately:
   
   Backend Server (provides API on port 8000):
      source $BACKEND_DIR/venv/bin/activate && cd $BACKEND_DIR && uvicorn app.main:app --reload
   
   Frontend Interface (web UI on port 5173):
      cd $FRONTEND_DIR && npm install && npm run dev
   
   AI Detection Module (ML service on port 8001):
      source $BACKEND_DIR/venv/bin/activate && cd $PROJECT_ROOT/ai_based_malware_detection && uvicorn routes:app --port 8001 --reload

3) To run static analysis tools from command line:
   
   Activate the virtual environment first:
      source $BACKEND_DIR/venv/bin/activate
   
   Basic Static Analysis (fast scan):
      cd $PROJECT_ROOT/matrisksBasicStatic && python3 matrisks.py --help
   
   Advanced Static Analysis (comprehensive scan):
      cd $PROJECT_ROOT/matrisksAdvanceStatic && python3 matrisks.py --help

4) To run dynamic analysis from command line:
   
   Activate the virtual environment:
      source $BACKEND_DIR/venv/bin/activate
   
   Analyze an APK file:
      cd $PROJECT_ROOT/matrisksDynamicAnalyzer && python cli.py analyze <apk-file>

========================================
EOF

