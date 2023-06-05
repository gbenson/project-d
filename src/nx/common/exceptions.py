class SecurityError(RuntimeError):
    """An insecure operation was attempted and blocked."""

class ChecksNotImplementedError(SecurityError):
    """Checks necessary to secure this operation are unimplemented."""
