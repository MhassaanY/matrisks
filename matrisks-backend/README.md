# Matrisks Backend

Backend API for Matrisks platform built with FastAPI, SQLAlchemy, and PostgreSQL.

## Setup Instructions

### Prerequisites
- Python 3.8+
- PostgreSQL

### Installation

1. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Create a PostgreSQL database:
```bash
createdb matrisks
```

4. Run migrations:
```bash
alembic upgrade head
```

### Environment Variables

Create a `.env` file in the root directory with the following variables:
```
DATABASE_URL=postgresql://postgres:postgres@localhost/matrisks
JWT_SECRET_KEY=your_secret_key
```

### Running the Development Server

```bash
uvicorn app.main:app --reload
```

The API will be available at http://localhost:8000

### API Documentation

- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc
