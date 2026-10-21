"""Custom exceptions for wayfind."""


class WayfindError(Exception):
    """Base exception for domain audit errors."""
    pass




class ConnectionError(WayfindError):
    """Raised when connection to AD fails."""
    pass


class EnumerationError(WayfindError):
    """Raised when enumeration fails."""
    pass

