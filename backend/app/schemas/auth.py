import re
from typing import List, Optional
from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator


_PASSWORD_RE = re.compile(
    r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()\-_=+\[\]{};:'\",.<>?/\\|`~]).{12,128}$"
)


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str
    full_name: Optional[str] = Field(None, max_length=255)
    invite: Optional[str] = None  # single-use access invite (required in the SaaS edition)

    @field_validator("password")
    @classmethod
    def validate_password_strength(cls, v: str) -> str:
        if not _PASSWORD_RE.match(v):
            raise ValueError(
                "Password must be 12–128 chars with at least one uppercase, "
                "lowercase, digit, and special character"
            )
        return v


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class MFARequiredResponse(BaseModel):
    mfa_required: bool = True
    mfa_token: str


class MFASetupResponse(BaseModel):
    secret: str
    otpauth_uri: str
    backup_codes: List[str]


class MFAVerifyRequest(BaseModel):
    code: str

    @field_validator("code")
    @classmethod
    def validate_totp_code(cls, v: str) -> str:
        if not v.isdigit() or len(v) != 6:
            raise ValueError("TOTP code must be exactly 6 digits")
        return v


class MFAAuthRequest(BaseModel):
    mfa_token: str
    code: str

    @field_validator("code")
    @classmethod
    def validate_mfa_code(cls, v: str) -> str:
        # 6-digit TOTP, or a 10-hex-char backup code (see AuthService._generate_backup_codes)
        normalized = v.replace("-", "").replace(" ", "").upper()
        if v.isdigit() and len(v) == 6:
            return v
        if len(normalized) == 10 and all(c in "0123456789ABCDEF" for c in normalized):
            return normalized
        raise ValueError("Code must be a 6-digit TOTP code or a 10-character backup code")


class LogoutRequest(BaseModel):
    all_devices: bool = False


class SessionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    created_at: str
    expires_at: str

    @field_validator("id", "created_at", "expires_at", mode="before")
    @classmethod
    def coerce_to_str(cls, v) -> str:
        return str(v)


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    email: str
    full_name: Optional[str] = None
    is_active: bool
    mfa_enabled: bool
    is_platform_admin: bool

    @field_validator("id", mode="before")
    @classmethod
    def coerce_uuid(cls, v) -> str:
        return str(v)


class UpdateMeRequest(BaseModel):
    full_name: Optional[str] = None

    @field_validator("full_name")
    @classmethod
    def validate_full_name(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        v = v.strip()
        if len(v) > 255:
            raise ValueError("full_name must be 255 characters or fewer")
        return v or None


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str

    @field_validator("new_password")
    @classmethod
    def validate_password_strength(cls, v: str) -> str:
        if not _PASSWORD_RE.match(v):
            raise ValueError(
                "Password must be 12–128 chars with at least one uppercase, "
                "lowercase, digit, and special character"
            )
        return v
