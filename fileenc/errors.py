"""Exception hierarchy for the file-encryption package.

Callers (e.g. Flask routes) catch FileEncError and show a *generic* message;
the specific subclass is for logging and tests, never for leaking details.
"""


class FileEncError(Exception):
    """Base class for all errors raised by this package."""


class ParameterError(FileEncError):
    """Caller supplied an invalid algorithm, key size, key, or password."""


class FormatError(FileEncError):
    """An encrypted file's header is malformed or unsupported."""


class AuthenticationError(FileEncError):
    """Authentication failed: wrong key, or the data was modified."""
