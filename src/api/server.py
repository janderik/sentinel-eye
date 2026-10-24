import logging
import time
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from src.api.routes import router

logger = logging.getLogger(__name__)


async def request_logging_middleware(request: Request, call_next: Callable):
    start = time.time()
    response = await call_next(request)
    elapsed = time.time() - start
    logger.info(
        f"{request.method} {request.url.path} - {response.status_code} "
        f"({elapsed:.3f}s)"
    )
    return response


async def error_handler_middleware(request: Request, call_next: Callable):
    try:
        return await call_next(request)
    except Exception:
        # Log the details server-side only; never leak internals to the client.
        logger.exception(f"Unhandled exception for {request.method} {request.url.path}")
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error"},
        )


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    from src.storage.database import get_db

    get_db().create_tables()
    logger.info("SentinelEye API started")
    yield


def create_app() -> FastAPI:
    app = FastAPI(
        lifespan=lifespan,
        title="SentinelEye API",
        description="Security Information and Event Management System - REST API",
        version="0.1.0",
        docs_url="/docs",
        redoc_url="/redoc",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.middleware("http")(request_logging_middleware)
    app.middleware("http")(error_handler_middleware)

    app.include_router(router, prefix="/api/v1")

    return app
