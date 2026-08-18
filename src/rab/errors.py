class RabError(Exception):
    """Expected user-facing RAB error."""


class PolicyError(RabError):
    """An operation violates preservation or rights policy."""


class IntegrityError(RabError):
    """Stored content or metadata failed validation."""

