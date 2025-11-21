"""
CypherRay ML Service - Clean Entry Point
Main application file for the FastAPI server.
"""

import os
import logging
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

# Check critical environment variables
openai_api_key = os.getenv('OPENAI_API_KEY')
anthropic_api_key = os.getenv('ANTHROPIC_API_KEY') or os.getenv('ANTRHOPIC_API_KEY')

if not openai_api_key:
    logger.error("Primary AI API key not found in environment variables!")
else:
    logger.info("✅ Primary AI provider configured")

if anthropic_api_key:
    logger.info("✅ Secondary AI provider configured")
else:
    logger.warning("⚠️ Secondary AI provider not configured (optional)")

# Check Angr availability
if check_angr_available():
    logger.info("✅ Angr loaded successfully")
else:
    logger.warning("⚠️ Angr not available - binary analysis will use fallback mode")

# Create FastAPI app
app = FastAPI(
    title="CypherRay - Cryptographic Binary Analysis System",
    description="AI-powered cryptographic algorithm detection and binary analysis using multi-model orchestration",
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
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


@app.on_event("startup")
async def startup_event():
    """Run on application startup."""
    logger.info("=" * 60)
    logger.info("CYPHERRAY ML SERVICE STARTING")
    logger.info("=" * 60)
    logger.info(f"Primary AI: {'✅ Configured' if openai_api_key else '❌ Missing'}")
    logger.info(f"Secondary AI: {'✅ Configured' if anthropic_api_key else '⚠️ Not configured'}")
    logger.info(f"Angr: {'✅ Available' if check_angr_available() else '❌ Not available'}")
    logger.info("=" * 60)


@app.on_event("shutdown")
async def shutdown_event():
    """Run on application shutdown."""
    logger.info("CypherRay ML Service shutting down...")


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
