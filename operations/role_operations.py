
from sqlalchemy.orm import Session
from models import Role
from models import User

DEFAULT_ROLES = [
    ("Super Admin", "Full system access"),
    ("Admin", "Administrative access"),
    ("Product Manager", "Manages products and categories"),
    ("Inventory Manager", "Manages inventory and warehouses"),
    ("Order Manager", "Manages customer orders"),
    ("Support Agent", "Handles customer support"),
    ("Customer", "Regular customer account"),
    ("Delivery Manager", "Manages deliveries"),
    ("Finance Manager", "Manages financial operations")
]


def create_default_roles(db: Session):
    created_roles = []

    for role_name, description in DEFAULT_ROLES:
        existing_role = db.query(Role).filter(
            Role.name == role_name
        ).first()

        if existing_role is None:
            new_role = Role(
                name=role_name,
                description=description
            )

            db.add(new_role)
            created_roles.append(role_name)

    db.commit()

    return created_roles


DEFAULT_PERMISSIONS = [
    ("user:create", "Create users"),
    ("user:read", "View users"),
    ("user:update", "Update users"),
    ("user:delete", "Delete users"),
    ("role:manage", "Manage roles"),
    ("product:create", "Create products"),
    ("product:read", "View products"),
    ("product:update", "Update products"),
    ("product:delete", "Delete products"),
    ("category:manage", "Manage product categories"),
    ("brand:manage", "Manage brands"),
    ("inventory:manage", "Manage inventory"),
    ("warehouse:manage", "Manage warehouses"),
    ("order:read", "View orders"),
    ("order:manage", "Manage orders"),
    ("delivery:manage", "Manage deliveries"),
    ("support:manage", "Manage customer support"),
    ("finance:manage", "Manage financial operations"),
    ("profile:manage", "Manage own profile")
]


def create_default_permissions(db: Session):
    from models import Permission

    created_permissions = []

    for permission_name, description in DEFAULT_PERMISSIONS:
        existing_permission = db.query(Permission).filter(
            Permission.name == permission_name
        ).first()

        if existing_permission is None:
            new_permission = Permission(
                name=permission_name,
                description=description
            )

            db.add(new_permission)
            created_permissions.append(permission_name)

    db.commit()

    return created_permissions


def assign_default_permissions(db: Session):
    from models import Permission

    role_permissions_map = {
        "Super Admin": [
            permission[0] for permission in DEFAULT_PERMISSIONS
        ],

        "Admin": [
            permission[0]
            for permission in DEFAULT_PERMISSIONS
            if permission[0] != "role:manage"
        ],

        "Product Manager": [
            "product:create",
            "product:read",
            "product:update",
            "product:delete",
            "category:manage",
            "brand:manage"
        ],

        "Inventory Manager": [
            "product:read",
            "inventory:manage",
            "warehouse:manage"
        ],

        "Order Manager": [
            "order:read",
            "order:manage"
        ],

        "Support Agent": [
            "user:read",
            "order:read",
            "support:manage"
        ],

        "Customer": [
            "profile:manage"
        ],

        "Delivery Manager": [
            "order:read",
            "delivery:manage"
        ],

        "Finance Manager": [
            "order:read",
            "finance:manage"
        ]
    }

    assigned_count = 0

    for role_name, permission_names in role_permissions_map.items():
        role = db.query(Role).filter(
            Role.name == role_name
        ).first()

        if role is None:
            raise ValueError(f"Role not found: {role_name}")

        for permission_name in permission_names:
            permission = db.query(Permission).filter(
                Permission.name == permission_name
            ).first()

            if permission is None:
                raise ValueError(
                    f"Permission not found: {permission_name}"
                )

            if permission not in role.permissions:
                role.permissions.append(permission)
                assigned_count += 1

    db.commit()

    return assigned_count


def assign_roles_to_user(
    db: Session,
    user_id: int,
    role_names: list[str]
):
    user = db.query(User).filter(
        User.id == user_id
    ).first()

    if user is None:
        return None

    roles = db.query(Role).filter(
        Role.name.in_(role_names),
        Role.is_active == True
    ).all()

    if len(roles) != len(set(role_names)):
        return False

    user.roles = roles

    db.commit()
    db.refresh(user)

    return user

def get_all_roles(db: Session):
    roles = db.query(Role).all()

    result = []

    for role in roles:
        result.append({
            "id": role.id,
            "name": role.name,
            "description": role.description,
            "is_active": role.is_active,
            "permissions": [
                permission.name
                for permission in role.permissions
            ]
        })

    return result


def get_user_roles(db: Session, user_id: int):
    user = db.query(User).filter(
        User.id == user_id
    ).first()

    if user is None:
        return None

    return {
        "user_id": user.id,
        "full_name": user.full_name,
        "email": user.email,
        "roles": [
            {
                "id": role.id,
                "name": role.name,
                "description": role.description
            }
            for role in user.roles
        ]
    }


def get_all_permissions(db: Session):
    from models import Permission

    permissions = db.query(Permission).order_by(
        Permission.id
    ).all()

    result = []

    for permission in permissions:
        result.append({
            "id": permission.id,
            "name": permission.name,
            "description": permission.description
        })

    return result


def update_role_permissions(
    db: Session,
    role_id: int,
    permission_names: list[str]
):
    from models import Permission

    role = db.query(Role).filter(
        Role.id == role_id
    ).first()

    if role is None:
        return None

    permission_names = list(set(permission_names))

    permissions = db.query(Permission).filter(
        Permission.name.in_(permission_names)
    ).all()

    if len(permissions) != len(permission_names):
        return False

    role.permissions = permissions

    db.commit()
    db.refresh(role)

    return role


def create_role(db: Session, name: str, description: str | None):
    existing_role = db.query(Role).filter(
        Role.name == name
    ).first()

    if existing_role:
        return None

    new_role = Role(
        name=name,
        description=description
    )

    db.add(new_role)
    db.commit()
    db.refresh(new_role)

    return new_role


def delete_role(db: Session, role_id: int):
    role = db.query(Role).filter(
        Role.id == role_id
    ).first()

    if role is None:
        return None

    if role.name in ["Super Admin", "Customer"]:
        return False

    db.delete(role)
    db.commit()

    return True
