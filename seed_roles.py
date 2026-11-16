
from database import SessionLocal
from operations.role_operations import create_default_roles

from operations.role_operations import (
    create_default_roles,
    create_default_permissions
)

from operations.role_operations import (
    create_default_roles,
    create_default_permissions,
    assign_default_permissions
)
db = SessionLocal()

try:
    created_roles = create_default_roles(db)

    if created_roles:
        print("Created roles:")
        for role in created_roles:
            print(role)
    else:
        print("All default roles already exist")

    created_permissions = create_default_permissions(db)

    print("\nCreated permissions:")

    for permission in created_permissions:
        print(permission)

    if not created_permissions:
        print("All default permissions already exist")

    assigned_count = assign_default_permissions(db)

    print(f"\nNew permission assignments: {assigned_count}")

finally:
    db.close()

