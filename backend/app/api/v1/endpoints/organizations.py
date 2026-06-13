from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status

from app.api.deps import CurrentUser, get_current_user, require_admin
from app.core.logging import get_logger
from app.schemas import OrganizationResponse, OrganizationUpdate
from app.services import organization_service

router = APIRouter()
log = get_logger(__name__)

@router.get(
    "/me",
    response_model=OrganizationResponse,
    summary="Fetch the caller's own organization",
    responses={
        401: {"description": "Missing or invalid auth token."},
        403: {"description": "User has no organization assigned."},
        404: {"description": "Organization not found or deleted."},
    },
)
async def get_my_organization(
    user: CurrentUser = Depends(get_current_user),
) -> OrganizationResponse:
    """Returns the authenticated user's organization."""
    if not user.organization_id:
        log.warning("user_has_no_org", user_id=user.id)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "no_organization",
                "message": (
                    "Your account is not assigned to any organization. "
                    "Contact your administrator."
                ),
            },
        )

    row = organization_service.get_organization_by_id(user.organization_id)

    if row is None:
        log.warning(
            "user_org_missing_or_deleted",
            user_id=user.id,
            organization_id=user.organization_id,
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error": "organization_not_found",
                "message": "Your organization no longer exists or has been deleted.",
            },
        )

    return OrganizationResponse.model_validate(row)

@router.patch(
    "/me",
    response_model=OrganizationResponse,
    summary="Update the caller's organization",
    responses={
        401: {"description": "Missing or invalid auth token."},
        403: {"description": "Requires admin or owner role."},
        404: {"description": "Organization not found."},
    },
)
async def update_my_organization(
    updates: OrganizationUpdate,
    user: CurrentUser = Depends(require_admin),
) -> OrganizationResponse:
    """Update mutable fields on the caller's own organization.

    Requires the ``admin`` or ``owner`` role.
    """
    if not user.organization_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "no_organization",
                "message": "Your account is not assigned to any organization.",
            },
        )

    # Pydantic v2: exclude_unset gives us only the fields the client sent
    diff = updates.model_dump(exclude_unset=True)

    if not diff:
        # nothing to change, return the current state
        row = organization_service.get_organization_by_id(user.organization_id)
    else:
        row = organization_service.update_organization(
            user.organization_id, updates=diff
        )
        log.info(
            "organization_updated",
            user_id=user.id,
            organization_id=user.organization_id,
            fields_changed=list(diff.keys()),
        )

    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error": "organization_not_found",
                "message": "Organization not found.",
            },
        )

    return OrganizationResponse.model_validate(row)