class PaError(Exception):
    """An error reported to the user as 'pa: error: ...' with exit code 2."""


class CaptureError(PaError):
    """A Capture is missing, of an unsupported type, or malformed."""


class SessionError(PaError):
    """CLI flags or a session file are inconsistent or incomplete."""


class DefinitionError(PaError):
    """A UART Definition is invalid."""


class EdsError(PaError):
    """An EDS/DCF file cannot be read."""
