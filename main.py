from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from core.config import get_settings
from core.logger import app_logger
from storage.db import db_manager
from storage.redis_queue import redis_manager
from api.routes import router as api_router
from api.websocket import router as ws_router


@asynccontextmanager
async def app_lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    settings = get_settings()
    app_logger.info(f"Booting {settings.APP_NAME} under environment: [bold green]{settings.APP_ENV}[/bold green]")

    pg_ready = await db_manager.check_connection()
    if pg_ready:
        await db_manager.create_tables()

    yield

    app_logger.info("Gracefully closing storage pools and connections...")
    await redis_manager.close()
    app_logger.info("System teardown completed.")


def create_application() -> FastAPI:
    settings = get_settings()
    app: FastAPI = FastAPI(
        title=settings.APP_NAME,
        version="1.0.0",
        lifespan=app_lifespan,
        docs_url="/docs",
        redoc_url="/redoc"
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"]
    )

    app.include_router(api_router)
    app.include_router(ws_router)

    return app


app: FastAPI = create_application()