# Matrisks - Security Analysis Platform

A full-stack web application for security analysis with a complete authentication system.

## Project Structure

This project is organized into two main components:

- **matrisks-frontend**: React frontend built with Vite
- **matrisks-backend**: FastAPI backend with PostgreSQL database

## Tech Stack

### Frontend
- React 18+ (with Vite)
- React Router for navigation
- Context API for state management
- Axios for API communication
- CSS Modules for styling

### Backend
- FastAPI for RESTful API
- PostgreSQL database
- SQLAlchemy ORM
- Alembic for database migrations
- Pydantic for data validation
- JWT for authentication
- Passlib & Bcrypt for password hashing

## Setup Instructions

### Prerequisites
- Node.js 16+ and npm
- Python 3.8+
- PostgreSQL database

### Backend Setup

1. Navigate to the backend directory:
```bash
cd matrisks-backend
```

2. Create a Python virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Create a PostgreSQL database:
```bash
createdb matrisks
```

5. Create a `.env` file in the backend root directory:
```
DATABASE_URL=postgresql://postgres:postgres@localhost/matrisks
JWT_SECRET_KEY=your_secret_key_here
```

6. Run database migrations:
```bash
alembic upgrade head
```

7. Start the backend server:
```bash
python main.py
```

The API will be available at http://localhost:8000 with documentation at http://localhost:8000/docs

### Frontend Setup

1. Navigate to the frontend directory:
```bash
cd matrisks-frontend
```

2. Install dependencies:
```bash
npm install
```

3. Create a `.env` file in the frontend root directory:
```
VITE_API_BASE_URL=http://localhost:8000
```

4. Start the development server:
```bash
npm run dev
```

The frontend will be available at http://localhost:5173

## Authentication Features

### Backend Endpoints

- `POST /auth/register`: Register a new user
- `POST /auth/login`: Login and receive access token
- `POST /auth/refresh`: Refresh access token using HTTP-only refresh token cookie
- `POST /auth/logout`: Log out user and clear refresh token

### Frontend Components

- AuthContext for managing auth state across the application
- Login and Registration forms with validation
- Protected routes for authenticated users
- Persistent sessions with automatic token refresh
- Secure token storage (HTTP-only cookies for refresh tokens)

## Security Features

- Password hashing with Bcrypt
- JWT authentication with short-lived access tokens
- HTTP-only cookies for refresh tokens to prevent XSS
- CSRF protection
- Password validation on both client and server

## Development

### Backend

- Run migrations: `alembic revision --autogenerate -m "your message"`
- Apply migrations: `alembic upgrade head`

### Frontend

- Build for production: `npm run build`
- Preview production build: `npm run preview`

## License

This project is licensed under the MIT License.
