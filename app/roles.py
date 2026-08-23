"""
Declarative role metadata for endpoints.

This is the FastAPI analogue of Nest's `@Roles(...roles: Role[])` decorator.
Nest stores this metadata via `Reflector`/`SetMetadata` and reads it back
inside a Guard through `ExecutionContext`. FastAPI has no built-in metadata
reflection layer, so the equivalent here is: stash the required roles as a
plain attribute directly on the route handler function, and have the guard
(`RolesGuard`) read it back off the *matched route's* endpoint at request
time via `request.scope["route"].endpoint`.

Usage:

    @router.get("/admin/dashboard")
    @Roles(Role.ADMIN)
    async def admin_dashboard(user: CurrentUser = Depends(RolesGuard())):
        ...

Order matters: `@Roles(...)` must sit *above* the route decorator
(`@router.get(...)`) so it decorates the already-route-registered function,
matching how you're already used to stacking decorators in Nest.
"""

import enum
from collections.abc import Callable
from typing import TypeVar


class Role(enum.StrEnum):
    """Application roles, carried inside the JWT `role` claim."""

    ADMIN = "admin"
    MANAGER = "manager"
    USER = "user"


ROLES_METADATA_KEY = "__required_roles__"

F = TypeVar("F", bound=Callable)


def Roles(*roles: Role) -> Callable[[F], F]:
    """Attach required-role metadata to an endpoint handler."""

    def decorator(func: F) -> F:
        setattr(func, ROLES_METADATA_KEY, roles)
        return func

    return decorator


def get_required_roles(endpoint: Callable) -> tuple[Role, ...]:
    """Read back the roles attached by `@Roles(...)`. Empty tuple = no restriction."""
    return getattr(endpoint, ROLES_METADATA_KEY, ())
