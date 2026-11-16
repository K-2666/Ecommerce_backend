
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from database import get_db
from schemas import (
    UserCreate,
    UserResponse,
    LoginRequest,
    TokenResponse,
    RefreshTokenRequest,
    RoleAssignmentRequest,
    RolePermissionUpdate,
    RoleCreate
)
from operations.user_operations import (
    register_user,
    login_user,
    refresh_user_tokens,
    logout_user,
    get_all_users
)
from dependencies import get_current_user, require_permission
from models import User
from operations.role_operations import (
    assign_roles_to_user,
    get_all_roles,
    get_user_roles,
    get_all_permissions,
    update_role_permissions,
    create_role,
    delete_role
)

from operations.user_operations import (
    register_user,
    login_user,
    refresh_user_tokens,
    logout_user,
    get_all_users,
    get_user_by_id,
    update_user,
    update_user_status,
    delete_user,
    search_users
)

from schemas import UserStatusUpdate

from schemas import UserUpdate
router = APIRouter(
    prefix="/auth",
    tags=["Authentication"]
)


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED
)
def register(user_data: UserCreate, db: Session = Depends(get_db)):
    new_user = register_user(db, user_data)

    if new_user is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already registered"
        )

    return new_user


@router.post("/login", response_model=TokenResponse)
def login(user_data: LoginRequest, db: Session = Depends(get_db)):
    tokens = login_user(
        db,
        user_data.email,
        user_data.password
    )

    if tokens is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password"
        )

    return tokens


@router.get("/me", response_model=UserResponse)
def get_my_profile(
    current_user: User = Depends(get_current_user)
):
    return current_user


@router.post("/refresh", response_model=TokenResponse)
def refresh_tokens(
    token_data: RefreshTokenRequest,
    db: Session = Depends(get_db)
):
    tokens = refresh_user_tokens(
        db,
        token_data.refresh_token
    )

    if tokens is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token"
        )

    return tokens


@router.post("/logout")
def logout(
    token_data: RefreshTokenRequest,
    db: Session = Depends(get_db)
):
    result = logout_user(
        db,
        token_data.refresh_token
    )

    if not result:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or already revoked refresh token"
        )

    return {
        "message": "Logout successful"
    }


@router.get("/permission-test")
def permission_test(
    current_user: User = Depends(
        require_permission("role:manage")
    )
):
    return {
        "message": "Permission granted",
        "user": current_user.email
    }


@router.put("/users/{user_id}/roles")
def assign_user_roles(
    user_id: int,
    role_data: RoleAssignmentRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_permission("role:manage")
    )
):
    user = assign_roles_to_user(
        db,
        user_id,
        role_data.role_names
    )

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    if user is False:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="One or more roles are invalid or inactive"
        )

    return {
        "message": "Roles assigned successfully",
        "user_id": user.id,
        "email": user.email,
        "roles": [role.name for role in user.roles]
    }


@router.get("/roles")
def list_roles(
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_permission("role:manage")
    )
):
    return get_all_roles(db)


@router.get("/users/{user_id}/roles")
def view_user_roles(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_permission("role:manage")
    )
):
    result = get_user_roles(db, user_id)

    if result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    return result


@router.get("/permissions")
def list_permissions(
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_permission("role:manage")
    )
):
    return get_all_permissions(db)


@router.put("/roles/{role_id}/permissions")
def update_permissions(
    role_id: int,
    permission_data: RolePermissionUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_permission("role:manage")
    )
):
    role = update_role_permissions(
        db,
        role_id,
        permission_data.permission_names
    )

    if role is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Role not found"
        )

    if role is False:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="One or more permissions are invalid"
        )

    return {
        "message": "Role permissions updated successfully",
        "role_id": role.id,
        "role_name": role.name,
        "permissions": [
            permission.name
            for permission in role.permissions
        ]
    }


@router.post("/roles", status_code=status.HTTP_201_CREATED)
def add_role(
    role_data: RoleCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_permission("role:manage")
    )
):
    role = create_role(
        db,
        role_data.name,
        role_data.description
    )

    if role is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Role already exists"
        )

    return {
        "message": "Role created successfully",
        "id": role.id,
        "name": role.name,
        "description": role.description,
        "is_active": role.is_active
    }


@router.delete("/roles/{role_id}")
def remove_role(
    role_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_permission("role:manage")
    )
):
    result = delete_role(db, role_id)

    if result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Role not found"
        )

    if result is False:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Core system roles cannot be deleted"
        )

    return {
        "message": "Role deleted successfully"
    }


@router.get("/users")
def list_users(
    skip: int = Query(0, ge=0),
    limit: int = Query(10, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_permission("user:read")
    )
):
    users = get_all_users(db, skip, limit)

    return {
        "total_returned": len(users),
        "users": [
            {
                "id": user.id,
                "full_name": user.full_name,
                "email": user.email,
                "phone": user.phone,
                "is_active": user.is_active,
                "is_verified": user.is_verified,
                "roles": [
                    role.name for role in user.roles
                ]
            }
            for user in users
        ]
    }


@router.get("/users/{user_id}")
def get_user_details(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_permission("user:read")
    )
):
    user = get_user_by_id(db, user_id)

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    return {
        "id": user.id,
        "full_name": user.full_name,
        "email": user.email,
        "phone": user.phone,
        "is_active": user.is_active,
        "is_verified": user.is_verified,
        "created_at": user.created_at,
        "roles": [
            role.name for role in user.roles
        ]
    }


@router.put("/users/{user_id}")
def update_user_details(
    user_id: int,
    user_data: UserUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_permission("user:update")
    )
):
    user = update_user(
        db,
        user_id,
        user_data
    )

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    if user is False:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already registered"
        )

    return {
        "message": "User updated successfully",
        "id": user.id,
        "full_name": user.full_name,
        "email": user.email,
        "phone": user.phone
    }


def update_user_status(db: Session, user_id: int, is_active: bool):
    user = db.query(User).filter(
        User.id == user_id
    ).first()

    if user is None:
        return None

    user.is_active = is_active

    db.commit()
    db.refresh(user)

    return user


@router.patch("/users/{user_id}/status")
def change_user_status(
    user_id: int,
    status_data: UserStatusUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_permission("user:update")
    )
):
    user = update_user_status(
        db,
        user_id,
        status_data.is_active
    )

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    return {
        "message": "User status updated successfully",
        "user_id": user.id,
        "full_name": user.full_name,
        "is_active": user.is_active
    }


@router.delete("/users/{user_id}")
def remove_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_permission("user:delete")
    )
):
    result = delete_user(
        db,
        user_id,
        current_user.id
    )

    if result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    if result is False:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You cannot delete your own account"
        )

    return {
        "message": "User deleted successfully",
        "user_id": user_id
    }


@router.get("/users/search")
def search_user_records(
    search_term: str = Query(..., min_length=2),
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_permission("user:read")
    )
):
    users = search_users(db, search_term)

    return {
        "total_returned": len(users),
        "users": [
            {
                "id": user.id,
                "full_name": user.full_name,
                "email": user.email,
                "phone": user.phone,
                "is_active": user.is_active,
                "is_verified": user.is_verified,
                "roles": [
                    role.name for role in user.roles
                ]
            }
            for user in users
        ]
    }
