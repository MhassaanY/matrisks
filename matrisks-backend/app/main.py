from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.routers import auth

app = FastAPI(
    title="Matrisks API",
    description="API for Matrisks platform",
    version="0.1.0"
)

# Configure CORS
origins = [
    "http://localhost",
    "http://localhost:5173",  # Default Vite dev server
    "http://127.0.0.1:5173",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(auth.router)

# Root endpoint
@app.get("/")
async def root():
    return {"message": "Welcome to Matrisks API"}
