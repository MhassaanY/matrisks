# MATRISKS - Android Security Analysis Framework

A comprehensive full-stack security analysis platform for Android applications featuring multiple analysis engines, machine learning-based malware detection, and dynamic runtime analysis.

## Overview

MATRISKS is an integrated Android security testing framework that combines:
- **Static Analysis** (Basic & Advanced) - Code-level vulnerability detection
- **Dynamic Analysis** - Runtime behavior monitoring with Frida instrumentation
- **AI-Powered Detection** - Machine learning-based malware classification
- **Web Interface** - Modern React-based UI for analysis management

## Features

### Analysis Engines

#### 1. Basic Static Analysis
- Fast APK security scanning
- Manifest analysis
- Permission checks
- Certificate validation
- Common vulnerability detection
- PDF/HTML/JSON/CSV reports

#### 2. Advanced Static Analysis
- Deep code analysis
- Control flow graph generation
- Taint analysis
- Advanced vulnerability patterns
- Comprehensive security reports

#### 3. Dynamic Analysis
- Runtime behavior monitoring (215+ APIs)
- Frida-based instrumentation
- Network traffic capture (HTTPS supported)
- File I/O tracking
- Cryptography operations monitoring
- SMS/Location/Contacts access detection
- Automated UI exploration
- Screenshot capture
- Logcat analysis

#### 4. AI Malware Detection
- Machine learning classification
- Feature extraction from APKs
- Trained model predictions
- Behavioral pattern analysis

### Platform Features
- User authentication & authorization
- Analysis history tracking
- Multi-format report generation
- Admin dashboard
- RESTful API with documentation
- Concurrent analysis support

## Quick Start

### Prerequisites
- **Python 3.8+** with pip
- **Node.js 16+** with npm
- **PostgreSQL 12+** database
- **4GB RAM** minimum (8GB recommended)
- **5GB disk space**

### Automated Setup

```bash
# Clone the repository
git clone https://github.com/MhassaanY/matrisks.git
cd matrisks

# Run automated setup
./setup.sh

# Install frontend dependencies
cd matrisks-frontend
npm install
cd ..

# Create PostgreSQL database
sudo -u postgres createdb matrisks

# Start all services
./start_all.sh
```

### Access the Application

- **Web Interface**: http://localhost:5173
- **Backend API**: http://localhost:8000
- **API Documentation**: http://localhost:8000/docs
- **AI Module**: http://localhost:8001

## System Requirements

See [REQUIREMENTS.md](REQUIREMENTS.md) for comprehensive system requirements, dependencies, and installation guides.

### Minimum Requirements
- CPU: Dual-core x86_64
- RAM: 4GB
- Disk: 5GB free space
- OS: Linux (Ubuntu 20.04+), macOS 11+, Windows WSL2

### For Dynamic Analysis (Optional)
- Android SDK command-line tools
- Android Emulator (API 30, x86_64)
- KVM support (Linux) or HAXM (macOS)
- Frida 16.1.4

## Architecture

```
matrisks/
├── matrisks-backend/          # FastAPI backend server
├── matrisks-frontend/         # React web interface
├── matrisksBasicStatic/       # Basic static analyzer
├── matrisksAdvanceStatic/     # Advanced static analyzer
├── matrisksDynamicAnalyzer/   # Dynamic runtime analyzer
├── ai_based_malware_detection/# ML-based detection
├── setup.sh                   # Automated setup script
├── start_all.sh              # Start all services
└── stop_all.sh               # Stop all services
```

## Tech Stack

### Frontend
- **React 19** with Vite
- React Router for navigation
- Axios for API communication
- Context API for state management

### Backend
- **FastAPI** - Modern Python web framework
- **PostgreSQL** - Primary database
- **SQLAlchemy** - Database ORM
- **Alembic** - Database migrations
- **JWT** - Authentication tokens
- **Bcrypt** - Password hashing

### Analysis Engines
- **Androguard 4.1+** - APK analysis
- **Frida 16.1.4** - Dynamic instrumentation
- **scikit-learn** - Machine learning
- **weasyprint** - PDF generation
- **NetworkX** - Graph analysis

## Usage

### Web Interface

1. **Register/Login** - Create an account or sign in
2. **Upload APK** - Select analysis type (Basic/Advanced/Dynamic/AI)
3. **View Results** - Access reports in HTML, JSON, or CSV format
4. **Analysis History** - Review past analyses in the dashboard

### Command Line

#### Basic Static Analysis
```bash
cd matrisksBasicStatic
source ../matrisks-backend/venv/bin/activate
python3 matrisks.py -f /path/to/app.apk
```

#### Advanced Static Analysis
```bash
cd matrisksAdvanceStatic
source ../matrisks-backend/venv/bin/activate
python3 matrisks.py -f /path/to/app.apk
```

#### Dynamic Analysis
```bash
cd matrisksDynamicAnalyzer
source venv/bin/activate
python cli.py analyze /path/to/app.apk --duration 60
```

### API Endpoints

Full API documentation available at http://localhost:8000/docs

**Authentication:**
- `POST /auth/register` - Create new user account
- `POST /auth/login` - User login (returns JWT token)
- `POST /auth/logout` - User logout

**Analysis:**
- `POST /analysis/scan` - Submit APK for analysis
- `GET /analysis/report/{analysis_id}` - Retrieve analysis report
- `GET /analysis/download/{analysis_id}/{format}` - Download report

**Admin:**
- `GET /admin/engines` - List available analysis engines
- `GET /admin/analysis-history` - View all analyses

## Security Features

- **Authentication**: JWT-based with HTTP-only cookies
- **Password Security**: Bcrypt hashing with salt
- **Input Validation**: Pydantic models on backend
- **File Upload Security**: Type validation and size limits
- **CSRF Protection**: Token-based request validation
- **SQL Injection Prevention**: SQLAlchemy ORM parameterization

## Development

### Backend Development

```bash
cd matrisks-backend
source venv/bin/activate

# Create new migration
alembic revision --autogenerate -m "description"

# Apply migrations
alembic upgrade head

# Run development server
uvicorn app.main:app --reload
```

### Frontend Development

```bash
cd matrisks-frontend

# Development mode
npm run dev

# Build for production
npm run build

# Preview production build
npm run preview
```

### Running Tests

```bash
# Backend tests
cd matrisks-backend
pytest

# Frontend tests
cd matrisks-frontend
npm test
```

## Analysis Output

### Report Formats

Each analysis generates multiple report formats:

- **HTML** - Interactive web-based report with visualizations
- **JSON** - Structured data for programmatic access
- **CSV** - Tabular format for spreadsheet analysis
- **PDF** - Printable document (Static analysis only)

### Dynamic Analysis Reports Include:

- API call logs (215+ monitored APIs)
- Network traffic capture
- HTTPS request/response data
- File I/O operations
- Cryptographic operations
- Permission-sensitive actions
- UI exploration paths
- Screenshots at intervals
- Logcat analysis

## Troubleshooting

### Common Issues

**PostgreSQL Connection Failed**
```bash
# Start PostgreSQL service
sudo systemctl start postgresql

# Verify database exists
psql -l | grep matrisks
```

**Frontend Not Loading**
```bash
# Clear npm cache
cd matrisks-frontend
rm -rf node_modules package-lock.json
npm install
```

**Dynamic Analysis KVM Error**
```bash
# Enable KVM (Linux)
sudo modprobe kvm kvm-amd  # or kvm-intel
sudo chmod 666 /dev/kvm
sudo usermod -aG kvm $USER
```

**Port Already in Use**
```bash
# Kill existing processes
./stop_all.sh

# Or manually
pkill -f "uvicorn|vite"
```

See [REQUIREMENTS.md](REQUIREMENTS.md) for detailed troubleshooting guides.

## Documentation

- [System Requirements](REQUIREMENTS.md) - Comprehensive dependency list
- [Backend API Docs](http://localhost:8000/docs) - Interactive API documentation
- [Dynamic Analyzer Setup](matrisksDynamicAnalyzer/README.md) - Android SDK configuration
- Component READMEs in each module directory

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request


## Acknowledgments

- **Androguard** - APK analysis library
- **Frida** - Dynamic instrumentation toolkit
- **FastAPI** - Modern Python web framework
- **React** - UI library

## Support

For issues and questions:
- GitHub Issues: https://github.com/MhassaanY/matrisks/issues
- Documentation: See component README files

---

**Built with for Android Security Research**
