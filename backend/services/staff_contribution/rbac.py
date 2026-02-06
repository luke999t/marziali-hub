"""
# AI_MODULE: RBAC
# AI_VERSION: 1.0.0
# AI_DESCRIPTION: Role-Based Access Control per sistema staff contribution
# AI_BUSINESS: Controlla accessi granulari per ruoli staff, verifica permessi,
#              gestisce gerarchia ruoli e permessi custom.
# AI_TEACHING: Pattern RBAC con ruoli gerarchici, permessi role-based + custom,
#              check ricorsivi per gerarchia, caching permessi.
# AI_COPYRIGHT: 2025 Media Center Arti Marziali - All Rights Reserved
# AI_CREATED: 2025-12-13

RBAC Module
===========

Role-Based Access Control con:
- Ruoli gerarchici (VIEWER < CONTRIBUTOR < TRANSLATOR < REVIEWER < MODERATOR < ADMIN)
- Permessi predefiniti per ruolo
- Permessi custom per utente
- Check gerarchia (admin eredita tutti i permessi)
- Caching per performance
"""

import asyncio
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Set, Any
import logging

from .schemas import StaffRole, Permission, StaffMember

logger = logging.getLogger(__name__)


@dataclass
class RolePermissions:
    """Permessi associati a un ruolo."""
    role: StaffRole
    permissions: Set[Permission]
    inherits_from: Optional[StaffRole] = None  # Ruolo da cui eredita

    def to_dict(self) -> Dict[str, Any]:
        """Converte in dizionario."""
        return {
            "role": self.role.value,
            "permissions": [p.value for p in self.permissions],
            "inherits_from": self.inherits_from.value if self.inherits_from else None,
        }


class RBAC:
    """
    Role-Based Access Control.

    Gestisce permessi basati su ruoli con ereditarieta'.

    Uso:
        rbac = RBAC()

        # Verifica permesso
        if rbac.has_permission(staff_member, Permission.EDIT_TRANSLATION):
            # Permesso concesso

        # Verifica ruolo minimo
        if rbac.has_role_level(staff_member, StaffRole.REVIEWER):
            # Ha almeno ruolo REVIEWER
    """

    # Permessi predefiniti per ruolo
    DEFAULT_ROLE_PERMISSIONS: Dict[StaffRole, Set[Permission]] = {
        StaffRole.VIEWER: {
            Permission.VIEW_CONTENT,
            Permission.VIEW_TRANSLATIONS,
        },
        StaffRole.CONTRIBUTOR: {
            Permission.VIEW_CONTENT,
            Permission.VIEW_TRANSLATIONS,
            Permission.CREATE_CONTRIBUTION,
            Permission.CREATE_COMMENT,
            Permission.EDIT_OWN_CONTRIBUTION,
            Permission.DELETE_OWN_CONTRIBUTION,
            Permission.SUBMIT_FOR_REVIEW,
        },
        StaffRole.TRANSLATOR: {
            Permission.VIEW_CONTENT,
            Permission.VIEW_TRANSLATIONS,
            Permission.CREATE_CONTRIBUTION,
            Permission.CREATE_TRANSLATION,
            Permission.CREATE_COMMENT,
            Permission.EDIT_OWN_CONTRIBUTION,
            Permission.EDIT_TRANSLATION,
            Permission.DELETE_OWN_CONTRIBUTION,
            Permission.SUBMIT_FOR_REVIEW,
        },
        StaffRole.REVIEWER: {
            Permission.VIEW_CONTENT,
            Permission.VIEW_TRANSLATIONS,
            Permission.VIEW_STAFF,
            Permission.CREATE_CONTRIBUTION,
            Permission.CREATE_TRANSLATION,
            Permission.CREATE_COMMENT,
            Permission.EDIT_OWN_CONTRIBUTION,
            Permission.EDIT_TRANSLATION,
            Permission.DELETE_OWN_CONTRIBUTION,
            Permission.SUBMIT_FOR_REVIEW,
            Permission.REVIEW_CONTRIBUTION,
            Permission.APPROVE_CONTRIBUTION,
            Permission.REJECT_CONTRIBUTION,
        },
        StaffRole.MODERATOR: {
            Permission.VIEW_CONTENT,
            Permission.VIEW_TRANSLATIONS,
            Permission.VIEW_AUDIT_LOG,
            Permission.VIEW_STAFF,
            Permission.CREATE_CONTRIBUTION,
            Permission.CREATE_TRANSLATION,
            Permission.CREATE_COMMENT,
            Permission.EDIT_OWN_CONTRIBUTION,
            Permission.EDIT_ANY_CONTRIBUTION,
            Permission.EDIT_TRANSLATION,
            Permission.DELETE_OWN_CONTRIBUTION,
            Permission.DELETE_ANY_CONTRIBUTION,
            Permission.SUBMIT_FOR_REVIEW,
            Permission.REVIEW_CONTRIBUTION,
            Permission.APPROVE_CONTRIBUTION,
            Permission.REJECT_CONTRIBUTION,
            Permission.PUBLISH_CONTENT,
            Permission.UNPUBLISH_CONTENT,
            Permission.REVERT_VERSION,
        },
        StaffRole.ADMIN: {
            # Admin ha tutti i permessi
            *Permission,
        },
    }

    # Gerarchia ruoli (chi eredita da chi)
    ROLE_HIERARCHY: Dict[StaffRole, Optional[StaffRole]] = {
        StaffRole.VIEWER: None,
        StaffRole.CONTRIBUTOR: StaffRole.VIEWER,
        StaffRole.TRANSLATOR: StaffRole.CONTRIBUTOR,
        StaffRole.REVIEWER: StaffRole.TRANSLATOR,
        StaffRole.MODERATOR: StaffRole.REVIEWER,
        StaffRole.ADMIN: StaffRole.MODERATOR,
    }

    def __init__(self):
        """Inizializza RBAC."""
        self._role_permissions: Dict[StaffRole, RolePermissions] = {}
        self._permission_cache: Dict[str, Set[Permission]] = {}  # member_id -> permissions
        self._initialize_role_permissions()

    def _initialize_role_permissions(self) -> None:
        """Inizializza permessi per ruoli."""
        for role in StaffRole:
            base_permissions = self.DEFAULT_ROLE_PERMISSIONS.get(role, set())
            inherits_from = self.ROLE_HIERARCHY.get(role)

            self._role_permissions[role] = RolePermissions(
                role=role,
                permissions=base_permissions,
                inherits_from=inherits_from,
            )

    def get_role_permissions(self, role: StaffRole, include_inherited: bool = True) -> Set[Permission]:
        """
        Ottiene permessi per un ruolo.

        Args:
            role: Ruolo staff
            include_inherited: Se includere permessi ereditati

        Returns:
            Set di Permission
        """
        role_perm = self._role_permissions.get(role)
        if role_perm is None:
            return set()

        permissions = role_perm.permissions.copy()

        if include_inherited and role_perm.inherits_from:
            # Aggiungi permessi ereditati ricorsivamente
            inherited = self.get_role_permissions(role_perm.inherits_from, True)
            permissions |= inherited

        return permissions

    def get_member_permissions(
        self,
        member: StaffMember,
        include_inherited: bool = True
    ) -> Set[Permission]:
        """
        Ottiene tutti i permessi di un membro.

        Args:
            member: StaffMember
            include_inherited: Se includere permessi ereditati dal ruolo

        Returns:
            Set di Permission
        """
        # Check cache
        cache_key = f"{member.id}_{include_inherited}"
        if cache_key in self._permission_cache:
            return self._permission_cache[cache_key]

        permissions = set()

        # Permessi dal ruolo
        try:
            role = StaffRole(member.role)
            permissions |= self.get_role_permissions(role, include_inherited)
        except ValueError:
            logger.warning(f"Ruolo non valido: {member.role}")

        # Permessi custom
        for perm_str in member.permissions:
            try:
                permissions.add(Permission(perm_str))
            except ValueError:
                logger.warning(f"Permesso non valido: {perm_str}")

        # Cache
        self._permission_cache[cache_key] = permissions
        return permissions

    def has_permission(
        self,
        member: StaffMember,
        permission: Permission,
        resource_owner_id: Optional[str] = None,
    ) -> bool:
        """
        Verifica se membro ha un permesso.

        Args:
            member: StaffMember da verificare
            permission: Permesso richiesto
            resource_owner_id: ID proprietario risorsa (per permessi *_OWN_*)

        Returns:
            True se ha permesso
        """
        if not member.is_active:
            return False

        # Check permessi speciali "own"
        if permission == Permission.EDIT_OWN_CONTRIBUTION:
            if resource_owner_id and resource_owner_id != member.id:
                # Deve avere EDIT_ANY per modificare risorse altrui
                return Permission.EDIT_ANY_CONTRIBUTION in self.get_member_permissions(member)
        elif permission == Permission.DELETE_OWN_CONTRIBUTION:
            if resource_owner_id and resource_owner_id != member.id:
                return Permission.DELETE_ANY_CONTRIBUTION in self.get_member_permissions(member)

        return permission in self.get_member_permissions(member)

    def has_any_permission(
        self,
        member: StaffMember,
        permissions: List[Permission],
    ) -> bool:
        """
        Verifica se membro ha almeno uno dei permessi.

        Args:
            member: StaffMember
            permissions: Lista permessi

        Returns:
            True se ha almeno un permesso
        """
        member_perms = self.get_member_permissions(member)
        return any(p in member_perms for p in permissions)

    def has_all_permissions(
        self,
        member: StaffMember,
        permissions: List[Permission],
    ) -> bool:
        """
        Verifica se membro ha tutti i permessi.

        Args:
            member: StaffMember
            permissions: Lista permessi

        Returns:
            True se ha tutti i permessi
        """
        member_perms = self.get_member_permissions(member)
        return all(p in member_perms for p in permissions)

    def has_role(self, member: StaffMember, role: StaffRole) -> bool:
        """
        Verifica se membro ha esattamente un ruolo.

        Args:
            member: StaffMember
            role: Ruolo da verificare

        Returns:
            True se ha il ruolo
        """
        try:
            return StaffRole(member.role) == role
        except ValueError:
            return False

    def has_role_level(self, member: StaffMember, min_role: StaffRole) -> bool:
        """
        Verifica se membro ha almeno un certo livello di ruolo.

        Args:
            member: StaffMember
            min_role: Ruolo minimo richiesto

        Returns:
            True se ha livello >= min_role
        """
        try:
            member_role = StaffRole(member.role)
            return member_role.level >= min_role.level
        except ValueError:
            return False

    def can_manage(self, manager: StaffMember, target: StaffMember) -> bool:
        """
        Verifica se manager puo' gestire target.

        Args:
            manager: Chi vuole gestire
            target: Chi deve essere gestito

        Returns:
            True se manager ha livello superiore a target
        """
        if not manager.is_active:
            return False

        try:
            manager_role = StaffRole(manager.role)
            target_role = StaffRole(target.role)
            return manager_role.level > target_role.level
        except ValueError:
            return False

    def can_assign_role(
        self,
        assigner: StaffMember,
        role_to_assign: StaffRole,
    ) -> bool:
        """
        Verifica se assigner puo' assegnare un ruolo.

        Args:
            assigner: Chi vuole assegnare
            role_to_assign: Ruolo da assegnare

        Returns:
            True se puo' assegnare (ha MANAGE_ROLES e livello superiore)
        """
        if not self.has_permission(assigner, Permission.MANAGE_ROLES):
            return False

        try:
            assigner_role = StaffRole(assigner.role)
            # Puo' assegnare solo ruoli inferiori al proprio
            return assigner_role.level > role_to_assign.level
        except ValueError:
            return False

    def can_access_project(self, member: StaffMember, project_id: str) -> bool:
        """
        Verifica se membro puo' accedere a un progetto.

        Args:
            member: StaffMember
            project_id: ID progetto

        Returns:
            True se ha accesso
        """
        if not member.is_active:
            return False

        # Admin vede tutto
        if self.has_permission(member, Permission.VIEW_ALL_PROJECTS):
            return True

        # Altrimenti deve essere assegnato al progetto
        return project_id in member.projects

    def grant_permission(self, member: StaffMember, permission: Permission) -> StaffMember:
        """
        Concede permesso custom a membro.

        Args:
            member: StaffMember
            permission: Permesso da concedere

        Returns:
            StaffMember aggiornato
        """
        if permission.value not in member.permissions:
            member.permissions.append(permission.value)
            self._invalidate_cache(member.id)
        return member

    def revoke_permission(self, member: StaffMember, permission: Permission) -> StaffMember:
        """
        Revoca permesso custom da membro.

        Args:
            member: StaffMember
            permission: Permesso da revocare

        Returns:
            StaffMember aggiornato
        """
        if permission.value in member.permissions:
            member.permissions.remove(permission.value)
            self._invalidate_cache(member.id)
        return member

    def change_role(self, member: StaffMember, new_role: StaffRole) -> StaffMember:
        """
        Cambia ruolo di un membro.

        Args:
            member: StaffMember
            new_role: Nuovo ruolo

        Returns:
            StaffMember aggiornato
        """
        member.role = new_role.value
        self._invalidate_cache(member.id)
        return member

    def assign_to_project(self, member: StaffMember, project_id: str) -> StaffMember:
        """
        Assegna membro a progetto.

        Args:
            member: StaffMember
            project_id: ID progetto

        Returns:
            StaffMember aggiornato
        """
        if project_id not in member.projects:
            member.projects.append(project_id)
        return member

    def remove_from_project(self, member: StaffMember, project_id: str) -> StaffMember:
        """
        Rimuove membro da progetto.

        Args:
            member: StaffMember
            project_id: ID progetto

        Returns:
            StaffMember aggiornato
        """
        if project_id in member.projects:
            member.projects.remove(project_id)
        return member

    def _invalidate_cache(self, member_id: str) -> None:
        """Invalida cache per un membro."""
        keys_to_remove = [k for k in self._permission_cache if k.startswith(member_id)]
        for key in keys_to_remove:
            del self._permission_cache[key]

    def clear_cache(self) -> None:
        """Pulisce tutta la cache."""
        self._permission_cache.clear()

    def get_role_info(self, role: StaffRole) -> Dict[str, Any]:
        """
        Ottiene info complete su un ruolo.

        Args:
            role: StaffRole

        Returns:
            Dict con info ruolo
        """
        permissions = self.get_role_permissions(role, include_inherited=True)
        direct_permissions = self.get_role_permissions(role, include_inherited=False)
        inherited_permissions = permissions - direct_permissions

        return {
            "role": role.value,
            "level": role.level,
            "inherits_from": self.ROLE_HIERARCHY.get(role, {}).value if self.ROLE_HIERARCHY.get(role) else None,
            "direct_permissions": [p.value for p in direct_permissions],
            "inherited_permissions": [p.value for p in inherited_permissions],
            "total_permissions": [p.value for p in permissions],
        }

    def get_all_roles_info(self) -> List[Dict[str, Any]]:
        """Ottiene info su tutti i ruoli."""
        return [self.get_role_info(role) for role in StaffRole]

    def check_access(
        self,
        member: StaffMember,
        action: str,
        resource_type: str,
        resource_id: str,
        resource_owner_id: Optional[str] = None,
        project_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Check completo accesso con dettagli.

        Args:
            member: StaffMember
            action: Azione richiesta (view, edit, delete, etc.)
            resource_type: Tipo risorsa (contribution, translation, etc.)
            resource_id: ID risorsa
            resource_owner_id: ID proprietario
            project_id: ID progetto

        Returns:
            Dict con risultato check e dettagli
        """
        result = {
            "allowed": False,
            "member_id": member.id,
            "action": action,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "reason": None,
            "missing_permissions": [],
        }

        # Check attivo
        if not member.is_active:
            result["reason"] = "member_inactive"
            return result

        # Check progetto
        if project_id and not self.can_access_project(member, project_id):
            result["reason"] = "project_access_denied"
            return result

        # Mappa action -> permission
        action_permission_map = {
            "view": Permission.VIEW_CONTENT,
            "edit": Permission.EDIT_OWN_CONTRIBUTION if resource_owner_id == member.id else Permission.EDIT_ANY_CONTRIBUTION,
            "delete": Permission.DELETE_OWN_CONTRIBUTION if resource_owner_id == member.id else Permission.DELETE_ANY_CONTRIBUTION,
            "approve": Permission.APPROVE_CONTRIBUTION,
            "reject": Permission.REJECT_CONTRIBUTION,
            "review": Permission.REVIEW_CONTRIBUTION,
            "publish": Permission.PUBLISH_CONTENT,
        }

        required_permission = action_permission_map.get(action)
        if required_permission is None:
            result["reason"] = "unknown_action"
            return result

        if self.has_permission(member, required_permission, resource_owner_id):
            result["allowed"] = True
            result["reason"] = "permission_granted"
        else:
            result["reason"] = "permission_denied"
            result["missing_permissions"] = [required_permission.value]

        return result
