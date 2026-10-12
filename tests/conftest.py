import sys
import types
from pathlib import Path
from unittest.mock import MagicMock, AsyncMock

# 1. Add backend/ and aegisx/ to Python path for testing
backend_dir = Path(__file__).resolve().parent.parent / "backend"
project_root = Path(__file__).resolve().parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))


# 2. Provide stubs for optional runtime libraries if running in minimal test env
if "structlog" not in sys.modules:
    try:
        import structlog
    except ImportError:
        structlog_mock = types.ModuleType("structlog")
        mock_logger = MagicMock()
        structlog_mock.get_logger = MagicMock(return_value=mock_logger)
        contextvars_mock = types.ModuleType("contextvars")
        contextvars_mock.clear_contextvars = MagicMock()
        contextvars_mock.bind_contextvars = MagicMock()
        structlog_mock.contextvars = contextvars_mock
        sys.modules["structlog"] = structlog_mock

if "pydantic_settings" not in sys.modules:
    try:
        import pydantic_settings
    except ImportError:
        ps_mock = types.ModuleType("pydantic_settings")
        class BaseSettings:
            def __init__(self, **kwargs):
                for k, v in kwargs.items():
                    setattr(self, k, v)
        class SettingsConfigDict(dict):
            pass
        ps_mock.BaseSettings = BaseSettings
        ps_mock.SettingsConfigDict = SettingsConfigDict
        sys.modules["pydantic_settings"] = ps_mock

if "pydantic" not in sys.modules:
    try:
        import pydantic
    except ImportError:
        pyd_mock = types.ModuleType("pydantic")
        class BaseModel:
            def __init__(self, **kwargs):
                for k, v in kwargs.items():
                    setattr(self, k, v)
            def model_dump(self):
                return self.__dict__
            def dict(self):
                return self.__dict__
        pyd_mock.BaseModel = BaseModel
        pyd_mock.Field = MagicMock(return_value=None)
        sys.modules["pydantic"] = pyd_mock

if "sqlalchemy" not in sys.modules:
    try:
        import sqlalchemy
    except ImportError:
        sa_mock = types.ModuleType("sqlalchemy")
        sa_mock.select = MagicMock(return_value=MagicMock())
        sa_mock.and_ = MagicMock()
        sa_mock.or_ = MagicMock()
        sa_mock.text = lambda s: s
        sa_mock.func = MagicMock()
        sa_mock.Column = MagicMock()
        sa_mock.String = MagicMock()
        sa_mock.Integer = MagicMock()
        sa_mock.BigInteger = MagicMock()
        sa_mock.DateTime = MagicMock()
        sa_mock.Boolean = MagicMock()
        sa_mock.Text = MagicMock()
        sa_mock.ForeignKey = MagicMock()
        sa_mock.JSON = MagicMock()
        sa_mock.Float = MagicMock()
        sa_mock.Enum = MagicMock()
        sa_mock.insert = MagicMock()
        sa_mock.update = MagicMock()
        sa_mock.delete = MagicMock()

        # ext.asyncio
        ext_mock = types.ModuleType("sqlalchemy.ext")
        asyncio_mock = types.ModuleType("sqlalchemy.ext.asyncio")
        class AsyncSession:
            pass
        asyncio_mock.AsyncSession = AsyncSession
        asyncio_mock.create_async_engine = MagicMock()
        asyncio_mock.async_sessionmaker = MagicMock()
        ext_mock.asyncio = asyncio_mock
        sa_mock.ext = ext_mock

        # orm
        orm_mock = types.ModuleType("sqlalchemy.orm")
        class DeclarativeBase:
            metadata = MagicMock()
            def __init__(self, **kwargs):
                for k, v in kwargs.items():
                    setattr(self, k, v)
        class Mapped:
            def __class_getitem__(cls, item):
                return cls
        orm_mock.DeclarativeBase = DeclarativeBase
        orm_mock.Mapped = Mapped
        orm_mock.mapped_column = MagicMock(return_value=None)
        orm_mock.relationship = MagicMock(return_value=None)
        orm_mock.sessionmaker = MagicMock()
        sa_mock.orm = orm_mock

        # dialects.postgresql
        dialects_mock = types.ModuleType("sqlalchemy.dialects")
        pg_mock = types.ModuleType("sqlalchemy.dialects.postgresql")
        pg_mock.UUID = MagicMock()
        pg_mock.JSONB = MagicMock()
        dialects_mock.postgresql = pg_mock
        sa_mock.dialects = dialects_mock

        sys.modules["sqlalchemy"] = sa_mock
        sys.modules["sqlalchemy.ext"] = ext_mock
        sys.modules["sqlalchemy.ext.asyncio"] = asyncio_mock
        sys.modules["sqlalchemy.orm"] = orm_mock
        sys.modules["sqlalchemy.dialects"] = dialects_mock
        sys.modules["sqlalchemy.dialects.postgresql"] = pg_mock
