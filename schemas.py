
from pydantic import BaseModel, EmailStr, ConfigDict, Field


class UserCreate(BaseModel):
    full_name: str = Field(min_length=3, max_length=150)
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)


class UserResponse(BaseModel):
    id: int
    full_name: str
    email: EmailStr
    phone: str | None
    is_active: bool
    is_verified: bool

    model_config = ConfigDict(from_attributes=True)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class RefreshTokenRequest(BaseModel):
    refresh_token: str


class RoleAssignmentRequest(BaseModel):
    role_names: list[str] = Field(min_length=1)


class RolePermissionUpdate(BaseModel):
    permission_names: list[str] = Field(default_factory=list)


class RoleCreate(BaseModel):
    name: str = Field(min_length=3, max_length=80)
    description: str | None = None


class UserUpdate(BaseModel):
    full_name: str | None = Field(default=None, min_length=3, max_length=150)
    email: EmailStr | None = None
    phone: str | None = Field(default=None, max_length=20)


class UserStatusUpdate(BaseModel):
    is_active: bool
