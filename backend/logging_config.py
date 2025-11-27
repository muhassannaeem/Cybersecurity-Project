"""
Centralized Logging Configuration Module

This module provides structured JSON logging for all microservices.
Logs are formatted in a consistent schema that can be easily parsed by Logstash.

Usage:
    from logging_config import setup_logging, get_logger
    
    logger = setup_logging(service_name="backend", log_level="INFO")
    logger.info("Service started", extra={"event_type": "system", "metadata": {"port": 5000}})
"""

import json
import logging
import os
import sys
from datetime import datetime
from typing import Optional, Dict, Any
import uuid


class JSONFormatter(logging.Formatter):
    """Custom JSON formatter for structured logging."""
    
    def __init__(self, service_name: str, environment: str = "development"):
        super().__init__()
        self.service_name = service_name
        self.environment = environment
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON."""
        log_data = {
            "@timestamp": datetime.utcnow().isoformat() + "Z",
            "service": self.service_name,
            "level": record.levelname,
            "message": record.getMessage(),
            "environment": self.environment,
        }
        
        # Add event_type if provided
        if hasattr(record, 'event_type'):
            log_data["event_type"] = record.event_type
        else:
            # Infer event_type from level
            if record.levelno >= logging.ERROR:
                log_data["event_type"] = "error"
            elif record.levelno >= logging.WARNING:
                log_data["event_type"] = "system"
            else:
                log_data["event_type"] = "system"
        
        # Add user_id if provided
        if hasattr(record, 'user_id'):
            log_data["user_id"] = record.user_id
        
        # Add ip_address if provided
        if hasattr(record, 'ip_address'):
            log_data["ip_address"] = record.ip_address
        
        # Add correlation_id if provided
        if hasattr(record, 'correlation_id'):
            log_data["correlation_id"] = record.correlation_id
        
        # Add metadata if provided
        if hasattr(record, 'metadata') and record.metadata:
            log_data["metadata"] = record.metadata
        
        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)
        
        # Add module and function info
        log_data["logger"] = record.name
        log_data["module"] = record.module
        log_data["function"] = record.funcName
        log_data["line"] = record.lineno
        
        return json.dumps(log_data, default=str)


def setup_logging(
    service_name: str,
    log_level: str = None,
    environment: str = None,
    log_file: Optional[str] = None
) -> logging.Logger:
    """
    Set up structured JSON logging for a service.
    
    Args:
        service_name: Name of the service (e.g., "backend", "decoy_generator")
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR). Defaults to INFO or from env
        environment: Environment name (development, production). Defaults to development or from env
        log_file: Optional path to log file. If None, logs only to console
    
    Returns:
        Configured logger instance
    """
    # Get log level from environment or use default
    if log_level is None:
        log_level = os.getenv('LOG_LEVEL', 'INFO').upper()
    
    # Get environment from env or use default
    if environment is None:
        environment = os.getenv('ENVIRONMENT', 'development')
    
    # Create logger
    logger = logging.getLogger(service_name)
    logger.setLevel(getattr(logging, log_level, logging.INFO))
    logger.handlers.clear()  # Remove any existing handlers
    
    # Create JSON formatter
    formatter = JSONFormatter(service_name=service_name, environment=environment)
    
    # Console handler (always add)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # File handler (if log_file specified)
    if log_file:
        # Ensure log directory exists
        log_dir = os.path.dirname(log_file)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)
        
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    
    return logger


def get_logger(service_name: str = None) -> logging.Logger:
    """
    Get an existing logger or create a new one.
    
    Args:
        service_name: Name of the service. If None, uses the calling module's name
    
    Returns:
        Logger instance
    """
    if service_name is None:
        # Try to infer from calling module
        import inspect
        frame = inspect.currentframe().f_back
        module_name = frame.f_globals.get('__name__', 'unknown')
        service_name = module_name.split('.')[0] if '.' in module_name else module_name
    
    logger = logging.getLogger(service_name)
    if not logger.handlers:
        # Logger not set up yet, set it up with defaults
        logger = setup_logging(service_name)
    
    return logger


def log_with_context(
    logger: logging.Logger,
    level: int,
    message: str,
    event_type: str = None,
    user_id: Optional[int] = None,
    ip_address: Optional[str] = None,
    correlation_id: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
    **kwargs
):
    """
    Log a message with additional context fields.
    
    Args:
        logger: Logger instance
        level: Log level (logging.INFO, logging.ERROR, etc.)
        message: Log message
        event_type: Type of event (system, threat, attack, audit, error)
        user_id: User ID if applicable
        ip_address: IP address if applicable
        correlation_id: Request correlation ID for tracing
        metadata: Additional metadata dictionary
        **kwargs: Additional fields to add to metadata
    """
    extra = {}
    
    if event_type:
        extra['event_type'] = event_type
    if user_id:
        extra['user_id'] = user_id
    if ip_address:
        extra['ip_address'] = ip_address
    if correlation_id:
        extra['correlation_id'] = correlation_id
    
    if metadata:
        extra['metadata'] = metadata
    elif kwargs:
        extra['metadata'] = kwargs
    
    logger.log(level, message, extra=extra)


# Convenience functions for common log operations
def log_info(logger: logging.Logger, message: str, **kwargs):
    """Log info message with context."""
    log_with_context(logger, logging.INFO, message, **kwargs)


def log_warning(logger: logging.Logger, message: str, **kwargs):
    """Log warning message with context."""
    log_with_context(logger, logging.WARNING, message, event_type="system", **kwargs)


def log_error(logger: logging.Logger, message: str, **kwargs):
    """Log error message with context."""
    log_with_context(logger, logging.ERROR, message, event_type="error", **kwargs)


def log_threat(logger: logging.Logger, message: str, **kwargs):
    """Log threat detection event."""
    log_with_context(logger, logging.WARNING, message, event_type="threat", **kwargs)


def log_attack(logger: logging.Logger, message: str, **kwargs):
    """Log attack behavior event."""
    log_with_context(logger, logging.WARNING, message, event_type="attack", **kwargs)


def log_audit(logger: logging.Logger, message: str, user_id: int = None, ip_address: str = None, **kwargs):
    """Log audit event."""
    log_with_context(logger, logging.INFO, message, event_type="audit", user_id=user_id, ip_address=ip_address, **kwargs)

