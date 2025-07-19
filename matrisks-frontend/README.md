# Matrisks Security Analysis Platform

A web application for security analysis of software and binary files.

## Frontend Setup

### Prerequisites
- Node.js 18+ and npm

### Installation
```bash
# Install dependencies
npm install
```

### Development
```bash
# Run development server
npm run dev
```

### Production Build
```bash
# Create production build
npm run build

# Preview production build
npm run preview
```

## Future FastAPI Integration

This frontend is designed to integrate with a FastAPI backend. The integration points are prepared in the codebase but not yet connected to an actual backend.

### Service Layer

The service layer in `src/services/` provides the interface that will connect to FastAPI. Key files:

- `api.js` - Core API service that handles API requests
- `fileService.js` - Handles file validation and uploading

### FastAPI Endpoint Requirements

When implementing the FastAPI backend, the following endpoints should be created:

1. **GET /api/analysis-types**
   - Returns list of available analysis types
   - Expected response: `[{ id: string, name: string, description: string }]`

2. **POST /api/analyze**
   - Accepts multipart form data with file and analysisType
   - Expected response: `{ status: string, message: string, id: string }`

3. **GET /api/analysis/result/{analysisId}**
   - Returns analysis results for a given ID
   - Expected response: `{ id: string, status: string, result: object }`

### Environment Variables

The frontend will look for these environment variables:

- `VITE_API_BASE_URL` - Base URL for API requests (default: '/api')
- `VITE_USE_MOCK_DATA` - Whether to use mock data (true/false)

### FastAPI Setup (Future)

1. Create a new FastAPI project in a separate directory:
   ```bash
   pip install fastapi uvicorn
   mkdir matrisks-backend
   cd matrisks-backend
   ```

2. Implement the required endpoints matching the frontend service layer

3. Enable CORS to allow requests from the frontend:
   ```python
   from fastapi.middleware.cors import CORSMiddleware
   
   app.add_middleware(
       CORSMiddleware,
       allow_origins=["http://localhost:5173"],  # Frontend dev server
       allow_credentials=True,
       allow_methods=["*"],
       allow_headers=["*"],
   )
   ```

4. Configure deployment to serve both frontend and backend, ensuring API requests are properly routed
