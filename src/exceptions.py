class DLLLoadError(Exception):
    """Base exception for DLL loading errors."""
    pass

class NotDotNetAssemblyError(DLLLoadError):
    """Raised when the DLL is not a .NET assembly."""
    pass

class ArchitectureMismatchError(DLLLoadError):
    """Raised when DLL architecture doesn't match Python process."""
    pass

class MissingDependencyError(DLLLoadError):
    """Raised when required dependencies are missing."""
    pass

class MethodNotFoundError(DLLLoadError):
    """Raised when a requested method doesn't exist in the DLL."""
    pass
