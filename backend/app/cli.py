"""Operator commands, run on the server.

    python -m app.cli invite you@example.com --name "Your Name"   # print a signup link
    python -m app.cli make-admin you@example.com                  # grant platform admin
    python -m app.cli create-admin admin@example.com --password   # create full admin account
    python -m app.cli edition                                     # show edition and signup mode

On a SaaS install nobody can sign up without an invite, so the first step is
`invite` for yourself, then `make-admin` once the account exists.
"""
import argparse
import asyncio
import getpass
import secrets
import string
import sys

from fastapi import HTTPException
from sqlalchemy import select

from app.core.config import settings
from app.core.security import hash_password
from app.db.models.user import User
from app.db.session import AsyncSessionLocal
from app.services.access_service import AccessService, registration_mode
from app.services.organization_service import OrganizationService


async def _invite(email: str, name: str, send: bool) -> None:
    async with AsyncSessionLocal() as db:
        invite = await AccessService(db).issue_invite(email, name or email, admin=None, send=send)
        await db.commit()
        print(f"Invite for {invite.email}, valid until {invite.expires_at:%Y-%m-%d %H:%M} UTC")
        print(f"{settings.FRONTEND_URL}/register?invite={invite.plain_token}")


async def _make_admin(email: str) -> None:
    async with AsyncSessionLocal() as db:
        user = (await db.execute(select(User).where(User.email == email.lower().strip()))).scalar_one_or_none()
        if user is None:
            sys.exit(f"No account for {email}. Create it first (see `invite`).")
        user.is_platform_admin = True
        await db.commit()
        print(f"{user.email} is now a platform admin.")


def _generate_secure_password(length: int = 24) -> str:
    """Generate a cryptographically secure password."""
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    # Ensure at least one of each required character type
    password = [
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.digits),
        secrets.choice("!@#$%^&*"),
    ]
    password += [secrets.choice(alphabet) for _ in range(length - 4)]
    secrets.SystemRandom().shuffle(password)
    return "".join(password)


async def _create_admin(email: str, name: str, password: str | None, org_name: str, org_slug: str) -> None:
    """Create a platform admin account with organization."""
    async with AsyncSessionLocal() as db:
        email = email.lower().strip()

        # Check if user already exists
        existing = (await db.execute(select(User).where(User.email == email))).scalar_one_or_none()
        if existing:
            sys.exit(f"Account {email} already exists. Use `make-admin` to grant admin rights.")

        # Generate or use provided password
        if password:
            final_password = password
        else:
            final_password = _generate_secure_password()

        # Validate password strength
        if len(final_password) < 12:
            sys.exit("Password must be at least 12 characters.")

        # Create user
        user = User(
            email=email,
            password_hash=hash_password(final_password),
            full_name=name or "Platform Administrator",
            is_platform_admin=True,
            is_active=True,
        )
        db.add(user)
        await db.flush()

        # Create organization for the admin
        org = await OrganizationService(db).create_organization(
            name=org_name or "Admin Workspace",
            slug=org_slug or f"admin-{secrets.token_hex(4)}",
            creator=user,
        )

        await db.commit()

        print("=" * 60)
        print("PLATFORM ADMIN ACCOUNT CREATED")
        print("=" * 60)
        print(f"Email:        {user.email}")
        print(f"Name:         {user.full_name}")
        print(f"User ID:      {user.id}")
        print(f"Organization: {org.name} ({org.slug})")
        print(f"Org ID:       {org.id}")
        print("-" * 60)
        if not password:
            print(f"Password:     {final_password}")
            print("-" * 60)
            print("IMPORTANT: Save this password securely. It cannot be recovered.")
        print("-" * 60)
        print("Next steps:")
        print(f"  1. Log in at {settings.FRONTEND_URL}/login")
        print("  2. Enable MFA in Account Settings (strongly recommended)")
        print("  3. Access requests will appear in Admin > Access Requests")
        print("=" * 60)


async def _edition() -> None:
    async with AsyncSessionLocal() as db:
        print(f"edition: {settings.MAILOX_EDITION}")
        print(f"registration: {await registration_mode(db)}")


def main() -> None:
    parser = argparse.ArgumentParser(prog="python -m app.cli", description="MAILOX operator commands")
    sub = parser.add_subparsers(dest="cmd", required=True)

    # invite
    p_inv = sub.add_parser("invite", help="create a single-use signup link")
    p_inv.add_argument("email")
    p_inv.add_argument("--name", default="")
    p_inv.add_argument("--no-email", action="store_true", help="only print the link")

    # make-admin
    p_adm = sub.add_parser("make-admin", help="grant platform admin to an existing account")
    p_adm.add_argument("email")

    # create-admin (new)
    p_create = sub.add_parser("create-admin", help="create a new platform admin account with organization")
    p_create.add_argument("email", help="admin email address")
    p_create.add_argument("--name", default="", help="full name (default: Platform Administrator)")
    p_create.add_argument("--password", action="store_true", help="prompt for password (otherwise auto-generated)")
    p_create.add_argument("--org-name", default="", help="organization name (default: Admin Workspace)")
    p_create.add_argument("--org-slug", default="", help="organization slug (default: auto-generated)")

    # edition
    sub.add_parser("edition", help="show edition and signup mode")

    args = parser.parse_args()

    try:
        if args.cmd == "invite":
            asyncio.run(_invite(args.email, args.name, send=not args.no_email))
        elif args.cmd == "make-admin":
            asyncio.run(_make_admin(args.email))
        elif args.cmd == "create-admin":
            pwd = None
            if args.password:
                pwd = getpass.getpass("Enter password (min 12 chars): ")
                pwd2 = getpass.getpass("Confirm password: ")
                if pwd != pwd2:
                    sys.exit("Passwords do not match.")
            asyncio.run(_create_admin(args.email, args.name, pwd, args.org_name, args.org_slug))
        else:
            asyncio.run(_edition())
    except HTTPException as exc:
        sys.exit(f"error: {exc.detail}")


if __name__ == "__main__":
    main()
