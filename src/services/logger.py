import logging
import sys
from pathlib import Path
from typing import Optional, Union
from rich.logging import RichHandler


class Logger:
    """
    A comprehensive logging class with colored console output and file logging.

    Features:
    - Colored terminal output using Rich
    - Optional file logging with timestamps
    - Beautiful tracebacks with code context
    - All log levels: DEBUG, INFO, WARNING, ERROR, CRITICAL
    - Singleton pattern (one logger per name)

    Usage:
        logger = Logger("my_app", log_file="logs/app.log", level="DEBUG")
        logger.info("Application started")
        logger.error("Error occurred", exc_info=True)
    """

    _instances = {}  # Singleton per logger name

    def __new__(cls, name: str = "app", *args, **kwargs):
        if name not in cls._instances:
            cls._instances[name] = super().__new__(cls)
        return cls._instances[name]

    def __init__(
            self,
            name: str = "app",
            level: str = "INFO",
            log_file: Optional[Union[str, Path]] = None,
            console_output: bool = True,
            file_output: bool = False,
            rich_tracebacks: bool = True,
    ):
        """
        Initialize the logger.

        Args:
            name: Logger name (e.g., "data_scraper", "my_app")
            level: Log level ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")
            log_file: Path to log file (e.g., "logs/app.log")
            console_output: Enable colored console output
            file_output: Enable file logging
            rich_tracebacks: Show beautiful tracebacks with context
        """
        if hasattr(self, "_initialized") and self._initialized:
            return

        self._name = name
        self._level = logging.getLevelName(level.upper())
        self._log_file = Path(log_file) if log_file else None
        self._console_output = console_output
        self._file_output = file_output or (log_file is not None)
        self._rich_tracebacks = rich_tracebacks

        self._logger = logging.getLogger(name)
        self._logger.setLevel(self._level)
        self._logger.handlers = []

        self._setup_handlers()
        self._initialized = True

    def _setup_handlers(self) -> None:
        """Configure logging handlers."""

        # Console handler with Rich (colored output)
        if self._console_output:
            rich_handler = RichHandler(
                level=self._level,
                rich_tracebacks=self._rich_tracebacks,
                tracebacks_width=None,
                tracebacks_extra_lines=3
            )
            rich_handler.setFormatter(
                logging.Formatter(
                    "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
                    "%Y-%m-%d %H:%M:%S"
                )
            )
            self._logger.addHandler(rich_handler)

        # File handler for persistent logs
        if self._file_output and self._log_file:
            self._log_file.parent.mkdir(parents=True, exist_ok=True)

            file_handler = logging.FileHandler(self._log_file)
            file_handler.setFormatter(
                logging.Formatter(
                    "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
                    "%Y-%m-%d %H:%M:%S"
                )
            )
            file_handler.setLevel(self._level)
            self._logger.addHandler(file_handler)

    # Logging methods
    def debug(self, message: str, *args, **kwargs) -> None:
        """DEBUG: Noisy diagnostics for debugging."""
        self._logger.debug(message, *args, **kwargs)

    def info(self, message: str, *args, **kwargs) -> None:
        """INFO: Normal operational messages."""
        self._logger.info(message, *args, **kwargs)

    def warning(self, message: str, *args, **kwargs) -> None:
        """WARNING: Unexpected but handled situations."""
        self._logger.warning(message, *args, **kwargs)

    def warn(self, message: str, *args, **kwargs) -> None:
        """Alias for warning()."""
        self.warning(message, *args, **kwargs)

    def error(self, message: str, *args, exc_info: bool = True, **kwargs) -> None:
        """ERROR: Error occurred but app continues."""
        if exc_info:
            kwargs["exc_info"] = True
        self._logger.error(message, *args, **kwargs)

    def critical(self, message: str, *args, exc_info: bool = True, **kwargs) -> None:
        """CRITICAL: Severe error, app may not continue."""
        if exc_info:
            kwargs["exc_info"] = True
        self._logger.critical(message, *args, **kwargs)

    def exception(self, message: str, *args, **kwargs) -> None:
        """Log ERROR with exception info automatically."""
        self.error(message, *args, exc_info=True, **kwargs)

    # Utility methods
    def set_level(self, level: str) -> None:
        """Change log level dynamically."""
        new_level = logging.getLevelName(level.upper())
        self._logger.setLevel(new_level)
        for handler in self._logger.handlers:
            handler.setLevel(new_level)

    def add_file_handler(self, log_file: Union[str, Path]) -> None:
        """Add file logging to existing logger."""
        self._log_file = Path(log_file)
        self._file_output = True
        self._log_file.parent.mkdir(parents=True, exist_ok=True)

        file_handler = logging.FileHandler(self._log_file)
        file_handler.setFormatter(
            logging.Formatter(
                "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
                "%Y-%m-%d %H:%M:%S"
            )
        )
        self._logger.addHandler(file_handler)

    @property
    def name(self) -> str:
        return self._name

    @property
    def level(self) -> str:
        return logging.getLevelName(self._level)


# Quick usage example
if __name__ == "__main__":
    logger = Logger(
        name="data_scraper",
        level="DEBUG",
        log_file="logs/scraper.log",
        console_output=True,
    )

    logger.debug("Starting scraping...")
    logger.info("Connected to API")
    logger.warning("Rate limit approaching")

    try:
        raise ValueError("Something went wrong!")
    except Exception:
        logger.exception("Failed to fetch data")

    logger.critical("App shutting down")