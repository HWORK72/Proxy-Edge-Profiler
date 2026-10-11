import logging
import sys
from rich.console import Console
from rich.logging import RichHandler
from core.config import get_settings


def configure_logger(name: str = "profiler") -> logging.Logger:
    settings = get_settings()
    logger: logging.Logger = logging.getLogger(name)

    if logger.handlers:
        return logger

    logger.setLevel(settings.LOG_LEVEL)
    logger.propagate = False

    console: Console = Console(file=sys.stdout, force_terminal=True)
    rich_handler: RichHandler = RichHandler(
        console=console,
        show_time=True,
        show_level=True,
        show_path=False,
        markup=True,
        rich_tracebacks=True,
        tracebacks_show_locals=False
    )
    formatter: logging.Formatter = logging.Formatter(
        fmt="%(message)s",
        datefmt="[%X]"
    )
    rich_handler.setFormatter(formatter)
    logger.addHandler(rich_handler)

    return logger


app_logger: logging.Logger = configure_logger()