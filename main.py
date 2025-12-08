"""
CypherRay ML Service - Clean Entry Point
Main application file for the FastAPI server.
"""

import os
import gc
import logging
from contextlib import asynccontextmanager
from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# Load environment variables
load_dotenv()

# Import routes
from src.api.routes import router
from src.core.angr_tools import check_angr_available
from src.utils.logger import get_logger

# Initialize logger
logger = get_logger(__name__)

# Suppress Angr's verbose logging
logging.getLogger('angr').setLevel(logging.CRITICAL)
logging.getLogger('cle').setLevel(logging.CRITICAL)
logging.getLogger('pyvex').setLevel(logging.CRITICAL)
logging.getLogger('cle.backends.macho').setLevel(logging.CRITICAL)

# Memory optimization for low-memory instances (512MB)
gc_threshold = int(os.getenv('GC_THRESHOLD', '50'))
gc.set_threshold(gc_threshold, 5, 5)  # More aggressive garbage collection
logger.info(f"🧹 Garbage collection threshold: {gc_threshold}")

# Check critical environment variables
anthropic_api_key = os.getenv('ANTHROPIC_API_KEY') or os.getenv('ANTRHOPIC_API_KEY')
environment = os.getenv('ENVIRONMENT', 'development')
log_level = os.getenv('LOG_LEVEL', 'INFO')

if not anthropic_api_key:
    logger.error("Anthropic API key not found in environment variables!")
    raise ValueError("ANTHROPIC_API_KEY must be set")
else:
    logger.info("✅ Claude AI provider configured")

# Check Angr availability
if check_angr_available():
    logger.info("✅ Angr loaded successfully")
else:
    logger.warning("⚠️ Angr not available - binary analysis will use fallback mode")

# Lifespan context manager for startup/shutdown events
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifespan events."""
    # Startup
    logger.info("=" * 60)
    logger.info("CYPHERRAY ML SERVICE STARTING")
    logger.info("=" * 60)
    logger.info(f"Environment: {environment}")
    logger.info(f"Log Level: {log_level}")
    logger.info(f"CORS Origins: {cors_origins}")
    logger.info(f"Claude AI: {'✅ Configured' if anthropic_api_key else '❌ Missing'}")
    logger.info(f"Angr: {'✅ Available' if check_angr_available() else '❌ Not available'}")
    logger.info("=" * 60)
    
    yield  # Application runs here
    
    # Shutdown
    logger.info("CypherRay ML Service shutting down...")

# Create FastAPI app with lifespan
app = FastAPI(
    title="CypherRay - Cryptographic Binary Analysis System",
    description="AI-powered cryptographic algorithm detection and binary analysis using multi-model orchestration",
    version="2.0.0",
    docs_url="/docs" if environment != "production" else None,
    redoc_url="/redoc" if environment != "production" else None,
    lifespan=lifespan
)

# CORS middleware - configurable origins
cors_origins_str = os.getenv('CORS_ORIGINS', '*')
cors_origins = cors_origins_str.split(',') if cors_origins_str != '*' else ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routes
app.include_router(router)

# Optional: Configure Logfire for production monitoring
try:
    import logfire
    logfire_token = os.getenv('LOGFIRE_TOKEN')
    if logfire_token:
        logfire.configure(token=logfire_token, inspect_arguments=False)
        logfire.instrument_fastapi(app)
        logger.info("✅ Logfire configured successfully")
    else:
        logfire.configure(inspect_arguments=False, send_to_logfire=False)
        logger.info("⚠️ Logfire running in local mode (not sending data)")
except ImportError:
    logger.info("ℹ️ Logfire not installed (optional)")
except Exception as e:
    logger.warning(f"⚠️ Logfire configuration skipped: {e}")


if __name__ == "__main__":
    import uvicorn
    
    port = int(os.getenv('PORT', 5000))
    logger.info(f"Starting server on port {port}...")
    
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=port,
        log_level="info"
    )
