#!/usr/bin/env bash
set -euo pipefail

# Root-level setup: creates/uses backend venv and installs all deps from requirements-all.txt

PROJECT_ROOT="$(cd "$(dirname "$0")" && pwd)"
BACKEND_DIR="$PROJECT_ROOT/matrisks-backend"
FRONTEND_DIR="$PROJECT_ROOT/matrisks-frontend"

python3 -m venv "$BACKEND_DIR/venv"
source "$BACKEND_DIR/venv/bin/activate"

pip install --upgrade pip
pip install -r "$PROJECT_ROOT/requirements-all.txt"

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

# Run migrations if alembic is configured
if [ -f "$BACKEND_DIR/alembic.ini" ]; then
	cd "$BACKEND_DIR"
	set +e
	alembic upgrade head
	UPGRADE_STATUS=$?
	set -e
	if [ $UPGRADE_STATUS -ne 0 ]; then
		echo "alembic upgrade failed (likely existing schema). Stamping head..."
		alembic stamp head
	fi
	cd "$PROJECT_ROOT"
fi

cat <<EOF
All dependencies installed into $BACKEND_DIR/venv
Next steps:
1) Start backend:
   source $BACKEND_DIR/venv/bin/activate && cd $BACKEND_DIR && uvicorn app.main:app --reload
2) Start frontend:
   cd $FRONTEND_DIR && npm install && npm run dev
3) To run static analysis tools, ensure you are in the project root and activate the virtual environment:
   source $BACKEND_DIR/venv/bin/activate
   Then, you can run the tools from their respective directories, for example:
   cd $PROJECT_ROOT/matrisksBasicStatic && python3 matrisks.py --help
EOF

