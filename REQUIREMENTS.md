# MATRISKS Framework - System Requirements

This document provides a comprehensive list of all system requirements, dependencies, and prerequisites needed to run the MATRISKS security analysis platform.

## Table of Contents
1. [System Requirements](#system-requirements)
2. [Software Dependencies](#software-dependencies)
3. [Python Packages](#python-packages)
4. [Frontend Dependencies](#frontend-dependencies)
5. [Optional Components](#optional-components)
6. [Installation Guides](#installation-guides)

---

## System Requirements

### Minimum Requirements
- **CPU**: Dual-core processor (x86_64 architecture)
- **RAM**: 4GB minimum
- **Disk Space**: 5GB free space
  - 2GB for application and dependencies
  - 1GB for Android SDK (Dynamic Analyzer)
  - 1GB for system images and AVDs
  - 1GB for analysis results and temporary files
- **Operating System**: 
  - Linux (Ubuntu 20.04+, Debian 11+, Fedora 35+)
  - macOS 11+ (Big Sur or later)
  - Windows 10+ with WSL2 (limited support)

### Recommended Requirements
- **CPU**: Quad-core processor with KVM support (Intel VT-x or AMD-V)
- **RAM**: 8GB or more
- **Disk Space**: 10GB+ free space
- **Operating System**: Linux with KVM support for optimal Dynamic Analyzer performance

---

## Software Dependencies

### Core Dependencies (Required)

#### 1. Python 3.8+
- **Purpose**: Core runtime for all backend services and analysis engines
- **Version**: 3.8, 3.9, 3.10, or 3.11 recommended
- **Installation**:
  ```bash
  # Ubuntu/Debian
  sudo apt update
  sudo apt install python3 python3-pip python3-venv
  
  # macOS
  brew install python@3.11
  
  # Fedora
  sudo dnf install python3 python3-pip
  ```

#### 2. Node.js 16+
- **Purpose**: Frontend development and build system
- **Version**: 16.x, 18.x, or 20.x (LTS versions recommended)
- **Installation**:
  ```bash
  # Ubuntu/Debian (using NodeSource)
  curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
  sudo apt install nodejs
  
  # macOS
  brew install node@20
  
  # Verify installation
  node --version  # Should show v20.x.x
  npm --version   # Should show 10.x.x
  ```

#### 3. PostgreSQL 12+
- **Purpose**: Primary database for user data, analysis records, and metadata
- **Version**: 12.x, 13.x, 14.x, or 15.x
- **Installation**:
  ```bash
  # Ubuntu/Debian
  sudo apt install postgresql postgresql-contrib
  sudo systemctl start postgresql
  sudo systemctl enable postgresql
  
  # macOS
  brew install postgresql@15
  brew services start postgresql@15
  
  # Create database
  sudo -u postgres createdb matrisks
  ```

### System Libraries (Required for PDF Generation)

#### 4. Cairo Graphics Library
- **Purpose**: PDF report generation via weasyprint
- **Installation**:
  ```bash
  # Ubuntu/Debian
  sudo apt install libcairo2 libcairo2-dev
  
  # macOS
  brew install cairo
  
  # Fedora
  sudo dnf install cairo cairo-devel
  ```

#### 5. Pango Text Layout Library
- **Purpose**: Text rendering in PDF reports
- **Installation**:
  ```bash
  # Ubuntu/Debian
  sudo apt install libpango-1.0-0 libpangocairo-1.0-0 libpangoft2-1.0-0
  
  # macOS
  brew install pango
  
  # Fedora
  sudo dnf install pango pango-devel
  ```

#### 6. GDK-PixBuf (Image Processing)
- **Purpose**: Image handling in reports
- **Installation**:
  ```bash
  # Ubuntu/Debian
  sudo apt install libgdk-pixbuf2.0-0 libgdk-pixbuf2.0-dev
  
  # macOS
  brew install gdk-pixbuf
  ```

---

## Python Packages

All Python packages are automatically installed via `requirements-all.txt` during setup.

### Backend API (`matrisks-backend/requirements.txt`)
| Package | Version | Purpose |
|---------|---------|---------|
| fastapi | 0.101.0 | Web API framework |
| uvicorn | 0.23.2 | ASGI web server |
| sqlalchemy | 2.0.19 | Database ORM |
| alembic | 1.11.3 | Database migrations |
| psycopg2-binary | 2.9.7 | PostgreSQL adapter |
| pydantic | 2.1.1 | Data validation |
| python-jose | 3.3.0 | JWT token handling |
| passlib | 1.7.4 | Password hashing |
| bcrypt | 4.0.1 | Cryptographic hashing |
| python-multipart | latest | File upload handling |
| scikit-learn | ≥1.3.0 | Machine learning |
| numpy | ≥1.24.0 | Numerical computing |
| pandas | ≥2.0.0 | Data analysis |
| androguard | ≥3.4.0 | APK analysis |
| aiofiles | ≥23.2.1 | Async file operations |

### AI Malware Detection (`ai_based_malware_detection/requirements.txt`)
| Package | Version | Purpose |
|---------|---------|---------|
| fastapi | ≥0.104.0 | API service |
| scikit-learn | ≥1.3.0 | ML models |
| pandas | ≥2.0.0 | Data processing |
| numpy | ≥1.24.0 | Array operations |
| androguard | ≥3.4.0 | APK feature extraction |
| python-magic | ≥0.4.27 | File type detection |

### Basic Static Analyzer (`matrisksBasicStatic/requirements.txt`)
| Package | Version | Purpose |
|---------|---------|---------|
| pymongo | 3.11.0 | MongoDB support (optional) |
| androguard | ≥3.4.0 | APK decompilation |
| dnspython | 2.0.0 | DNS utilities |
| weasyprint | latest | PDF generation |

### Advanced Static Analyzer (`matrisksAdvanceStatic/requirements.txt`)
| Package | Version | Purpose |
|---------|---------|---------|
| androguard | ≥4.1.2 | Deep APK analysis |
| networkx | 3.5 | Control flow graphs |
| matplotlib | 3.10.6 | Graph visualization |
| pydot | 4.0.1 | DOT graph rendering |
| lxml | 6.0.1 | XML/HTML processing |
| PyYAML | 6.0.2 | Configuration files |
| weasyprint | 66.0 | PDF reports |
| numpy | 2.3.3 | Numerical operations |

### Dynamic Analyzer (`matrisksDynamicAnalyzer/requirements.txt`)
| Package | Version | Purpose |
|---------|---------|---------|
| frida | 16.1.4 | Runtime instrumentation |
| frida-tools | 12.2.1 | Frida CLI utilities |
| androguard | ≥4.1.2 | APK analysis |
| pyyaml | ≥6.0.1 | Config management |
| psutil | ≥5.9.5 | Process monitoring |
| requests | ≥2.31.0 | HTTP requests |
| tqdm | ≥4.66.1 | Progress bars |
| colorlog | ≥6.8.0 | Colored logging |

---

## Frontend Dependencies

### NPM Packages (`matrisks-frontend/package.json`)

#### Production Dependencies
| Package | Version | Purpose |
|---------|---------|---------|
| react | 19.0.0 | UI framework |
| react-dom | 19.0.0 | DOM rendering |
| react-router-dom | 7.6.0 | Client-side routing |
| axios | 1.9.0 | HTTP client |

#### Development Dependencies
| Package | Version | Purpose |
|---------|---------|---------|
| vite | 6.3.1 | Build tool and dev server |
| @vitejs/plugin-react | 4.3.4 | React integration |
| eslint | 9.22.0 | Code linting |
| eslint-plugin-react-hooks | 5.2.0 | React hooks linting |

---

## Optional Components

### Dynamic Analyzer Requirements (Optional)

These are only required if you plan to use the Dynamic Analysis feature:

#### 1. Android SDK Command-Line Tools
- **Purpose**: Android emulator and development tools
- **Size**: ~100MB download, ~500MB installed
- **Installation**: Automated via `python setup.py` in `matrisksDynamicAnalyzer/`
- **Manual Installation**:
  ```bash
  # Download from: https://developer.android.com/studio#command-tools
  wget https://dl.google.com/android/repository/commandlinetools-linux-9477386_latest.zip
  unzip commandlinetools-linux-9477386_latest.zip
  mkdir -p $HOME/Android/Sdk/cmdline-tools
  mv cmdline-tools $HOME/Android/Sdk/cmdline-tools/latest
  
  # Add to PATH
  export ANDROID_SDK_ROOT=$HOME/Android/Sdk
  export PATH=$ANDROID_SDK_ROOT/cmdline-tools/latest/bin:$PATH
  export PATH=$ANDROID_SDK_ROOT/platform-tools:$PATH
  ```

#### 2. Android System Image (API 30)
- **Purpose**: Android 11 emulator system image
- **Architecture**: x86_64 (Intel/AMD compatible)
- **Size**: ~800MB download
- **Installation**: Automated via setup script
- **Manual Installation**:
  ```bash
  sdkmanager "system-images;android-30;google_apis;x86_64"
  sdkmanager "platform-tools" "emulator"
  ```

#### 3. Android Virtual Device (AVD)
- **Purpose**: Emulator instance for app testing
- **Configuration**: Pixel 5, API 30, 2GB RAM, x86_64
- **Installation**: Automated via setup script
- **Manual Creation**:
  ```bash
  avdmanager create avd \
    -n Pixel_5_API_30 \
    -k "system-images;android-30;google_apis;x86_64" \
    -d pixel_5
  ```

#### 4. KVM Support (Linux Only)
- **Purpose**: Hardware acceleration for Android emulator
- **Requirements**: Intel VT-x or AMD-V capable CPU
- **Installation**:
  ```bash
  # Check if supported
  egrep -c '(vmx|svm)' /proc/cpuinfo  # Should return > 0
  
  # Install KVM
  sudo apt install qemu-kvm libvirt-daemon-system libvirt-clients bridge-utils
  
  # Enable KVM modules
  sudo modprobe kvm
  sudo modprobe kvm-amd  # or kvm-intel for Intel CPUs
  
  # Set permissions
  sudo usermod -aG kvm $USER
  sudo chmod 666 /dev/kvm
  
  # Verify
  ls -l /dev/kvm  # Should show crw-rw-rw-
  ```

#### 5. Frida Server
- **Purpose**: Runtime instrumentation framework
- **Version**: 16.1.4 (must match frida Python package)
- **Architecture**: x86_64 for emulator
- **Size**: ~40MB
- **Installation**: Automated via setup script
- **Manual Download**:
  ```bash
  wget https://github.com/frida/frida/releases/download/16.1.4/frida-server-16.1.4-android-x86_64.xz
  unxz frida-server-16.1.4-android-x86_64.xz
  chmod +x frida-server-16.1.4-android-x86_64
  ```

---

## Installation Guides

### Quick Setup (Recommended)

```bash
# 1. Clone repository
git clone https://github.com/MhassaanY/matrisks.git
cd matrisks

# 2. Run automated setup
./setup.sh

# 3. Install frontend dependencies
cd matrisks-frontend
npm install
cd ..

# 4. Configure database (create PostgreSQL database)
sudo -u postgres createdb matrisks

# 5. (Optional) Setup Dynamic Analyzer
cd matrisksDynamicAnalyzer
python setup.py
cd ..

# 6. Start all services
./start_all.sh
```

### Manual Setup

See individual component README files:
- Backend: `matrisks-backend/README.md`
- Frontend: `matrisks-frontend/README.md`
- Dynamic Analyzer: `matrisksDynamicAnalyzer/README.md`
- AI Module: `ai_based_malware_detection/README.md`
- Basic Static: `matrisksBasicStatic/README.md`
- Advanced Static: `matrisksAdvanceStatic/README.md`

### Verification

After installation, verify all components:

```bash
# Check Python packages
source matrisks-backend/venv/bin/activate
pip list | grep -E "fastapi|uvicorn|androguard|frida"

# Check frontend packages
cd matrisks-frontend
npm list --depth=0

# Check PostgreSQL
psql -l | grep matrisks

# Check Android SDK (if installed)
which adb
adb --version

# Check KVM (Linux only)
ls -l /dev/kvm
```

---

## Troubleshooting

### Common Issues

**Issue**: `ImportError: No module named 'cairo'`
- **Solution**: Install Cairo system library: `sudo apt install libcairo2-dev`

**Issue**: `psycopg2.OperationalError: connection refused`
- **Solution**: Ensure PostgreSQL is running: `sudo systemctl start postgresql`

**Issue**: KVM permission denied
- **Solution**: 
  ```bash
  sudo chmod 666 /dev/kvm
  sudo usermod -aG kvm $USER
  # Log out and back in
  ```

**Issue**: npm install fails
- **Solution**: Update Node.js to LTS version: `nvm install --lts`

---

## Platform-Specific Notes

### Ubuntu/Debian
- Use `apt` package manager
- Enable KVM for best Dynamic Analyzer performance
- All features fully supported

### macOS
- Use `brew` package manager
- Use HAXM instead of KVM for emulator acceleration
- PDF generation may require additional Xcode tools

### Windows (WSL2)
- Limited support, use native Linux for production
- KVM not available in WSL2 (slow emulator)
- PostgreSQL should run in WSL2, not Windows

---

## Resource Usage

### Typical Resource Consumption

| Component | CPU (Idle) | CPU (Active) | RAM | Disk |
|-----------|------------|--------------|-----|------|
| Backend API | <1% | 5-15% | 200MB | 50MB |
| Frontend Dev Server | <1% | 5-10% | 100MB | 20MB |
| AI Module | <1% | 20-40% | 500MB | 100MB |
| Basic Static Analyzer | - | 10-30% | 300MB | 50MB/scan |
| Advanced Static Analyzer | - | 30-60% | 800MB | 200MB/scan |
| Dynamic Analyzer | - | 50-80% | 2GB | 500MB/scan |
| PostgreSQL | <1% | 5-10% | 100MB | 100MB |

**Total (All Running)**: ~4GB RAM, ~1GB disk per analysis session

---

## Support

For additional help:
- Check component-specific README files
- Review logs in `matrisks/logs/`
- Report issues on GitHub: https://github.com/MhassaanY/matrisks
