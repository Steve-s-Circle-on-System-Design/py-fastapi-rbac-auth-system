"""
RolesGuard — FastAPI's analogue of Nest's `RolesGuard`.

Nest's guard pulls the `ExecutionContext`, reads metadata off the handler
via `Reflector`, and compares it to `request.user`. There is no
`ExecutionContext` in FastAPI, but `Request.scope["route"]` gives us the
matched `APIRoute` for the current request, whose `.endpoint` is the exact
function `@Roles(...)` was applied to — that's the metadata source.

Usage on a route:

    @router.get("/admin/dashboard")
    @Roles(Role.ADMIN)
    async def admin_dashboard(user: CurrentUser = Depends(RolesGuard())):
        return {"message": f"Welcome, {user.id}"}

If a route has no `@Roles(...)` on it, the guard is a no-op (any
authenticated user passes) — it never fails open on *authentication*,
only on the role check.
"""

from typing import Annotated

from fastapi import Depends, HTTPException, Request, status

from app.roles import get_required_roles
from app.security import CurrentUser, get_current_user


class RolesGuard:
    """Callable FastAPI dependency enforcing `@Roles(...)` metadata."""

    async def __call__(
        self,
        request: Request,
        current_user: Annotated[CurrentUser, Depends(get_current_user)],
    ) -> CurrentUser:
        route = request.scope.get("route")
        endpoint = getattr(route, "endpoint", None)
        required_roles = get_required_roles(endpoint) if endpoint else ()

        if required_roles and current_user.role not in required_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not have permission to access this resource.",
            )

        return current_user
