"""
AETHER Role-Based Access Control (Item 128).
Manages user roles (Admin, Operator, ReadOnly) and permission checks.
"""
from enum import Enum
from typing import List

class Role(Enum):
    ADMIN = "admin"       # Full control, including kill-cord
    OPERATOR = "operator" # Can run scans and view findings
    VIEWER = "viewer"     # Read-only access

class RBACManager:
    def __init__(self):
        self.permissions = {
            Role.ADMIN: ["scan:start", "scan:stop", "findings:view", "findings:delete", "system:kill"],
            Role.OPERATOR: ["scan:start", "findings:view"],
            Role.VIEWER: ["findings:view"]
        }

    def has_permission(self, role: Role, action: str) -> bool:
        return action in self.permissions.get(role, [])

rbac_manager = RBACManager()
