from collections.abc import AsyncGenerator
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine
)
from sqlalchemy.orm import DeclarativeBase
from core.config import get_settings
from core.logger import app_logger


class Base(DeclarativeBase):
    pass


class DatabaseManager:
    def __init__(self) -> None:
        settings = get_settings()
        self._engine: AsyncEngine = create_async_engine(
            settings.postgres_async_url,
            echo=False,
            pool_size=20,
            max_overflow=10,
            pool_pre_ping=True
        )
        self._session_factory: async_sessionmaker[AsyncSession] = async_sessionmaker(
            bind=self._engine,
            class_=AsyncSession,
            expire_on_commit=False,
            autoflush=False
        )

    @property
    def session_factory(self) -> async_sessionmaker[AsyncSession]:
        return self._session_factory

    async def get_session(self) -> AsyncGenerator[AsyncSession, None]:
        async with self._session_factory() as session:
            try:
                yield session
            except Exception as error:
                await session.rollback()
                app_logger.error(f"Database session rolled back due to error: {error}")
                raise

    async def check_connection(self) -> bool:
        try:
            async with self._engine.connect() as connection:
                from sqlalchemy import text
                await connection.execute(text("SELECT 1"))
                return True
        except Exception as error:
            app_logger.warning(f"PostgreSQL connection offline or unreachable: {error}")
            return False

    async def create_tables(self) -> None:
        try:
            async with self._engine.begin() as connection:
                await connection.run_sync(Base.metadata.create_all)
            app_logger.info("Database schemas initialized successfully.")
        except Exception as error:
            app_logger.warning(f"Skipping table creation (DB offline): {error}")


db_manager: DatabaseManager = DatabaseManager()