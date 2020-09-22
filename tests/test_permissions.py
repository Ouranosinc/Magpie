import unittest

from magpie import __meta__, models
from magpie.permissions import Access, Permission, PermissionSet, Scope, format_permissions
from tests import runner, utils


@runner.MAGPIE_TEST_LOCAL
@runner.MAGPIE_TEST_UTILS
class TestPermissions(unittest.TestCase):
    def test_format_permissions(self):
        utils.warn_version(__meta__.__version__, "permission format validation", "2.1", skip=True)

        usr_perm = models.UserPermission()
        usr_perm.perm_name = Permission.GET_FEATURE.value
        grp_perm = models.GroupPermission()
        grp_perm.perm_name = "write-match"      # using string for backward compatibility
        dup_perm = Permission.READ.value        # only one should remain in result
        dup_usr_perm = models.UserPermission()
        dup_usr_perm.perm_name = dup_perm       # also only one remains although different type
        only_perm = Permission.GET_CAPABILITIES
        deny_match_perm = PermissionSet(Permission.GET_LEGEND_GRAPHIC, Access.DENY, Scope.MATCH)
        deny_str_perm = Permission.GET_MAP.value + "-" + Access.DENY.value
        deny_recur_perm = PermissionSet(Permission.GET_METADATA, Access.DENY, Scope.RECURSIVE)
        # purposely use a random order to test sorting simultaneously to duplicate removal
        any_perms = [deny_match_perm, dup_perm, only_perm, usr_perm, dup_usr_perm, grp_perm,
                     deny_str_perm, deny_recur_perm, deny_recur_perm]

        format_perms = format_permissions(any_perms)
        expect_names = [
            # both implicit/explicit variants added for backward compatibility and new format for each applicable case
            only_perm.value,
            str(PermissionSet(only_perm, Access.ALLOW, Scope.RECURSIVE)),
            usr_perm.perm_name,
            str(PermissionSet(usr_perm.perm_name)),
            # deny only have explicit representation
            str(deny_match_perm),
            str(PermissionSet(deny_str_perm, Access.DENY, Scope.RECURSIVE)),
            str(PermissionSet(deny_recur_perm.name, deny_recur_perm.access, Scope.RECURSIVE)),
            dup_perm,  # only one, other not present
            str(PermissionSet(dup_perm, Access.ALLOW, Scope.RECURSIVE)),
            grp_perm.perm_name,
            str(PermissionSet(grp_perm.perm_name, Access.ALLOW, Scope.MATCH)),
        ]
        expect_perms = [
            PermissionSet(Permission.GET_CAPABILITIES, Access.ALLOW, Scope.RECURSIVE).json(),
            PermissionSet(Permission.GET_FEATURE, Access.ALLOW, Scope.RECURSIVE).json(),
            PermissionSet(Permission.GET_LEGEND_GRAPHIC, Access.DENY, Scope.MATCH).json(),
            PermissionSet(Permission.GET_MAP, Access.DENY, Scope.RECURSIVE).json(),
            PermissionSet(Permission.GET_METADATA, Access.DENY, Scope.RECURSIVE).json(),
            PermissionSet(Permission.READ, Access.ALLOW, Scope.RECURSIVE).json(),
            PermissionSet(Permission.WRITE, Access.ALLOW, Scope.MATCH).json(),
        ]
        utils.check_all_equal(format_perms["permission_names"], expect_names, any_order=False)
        utils.check_all_equal(format_perms["permissions"], expect_perms, any_order=False)

    def test_permission_set_convert(self):
        """
        Validate various implicit conversion of permission name string to explicit definition.
        """
        utils.warn_version(__meta__.__version__, "permission implicit/explicit conversion", "2.1", skip=True)

        perm = PermissionSet("read")  # old implicit format
        utils.check_val_equal(perm.name, Permission.READ)
        utils.check_val_equal(perm.access, Access.ALLOW)
        utils.check_val_equal(perm.scope, Scope.RECURSIVE)
        perm = PermissionSet("read-match")  # old format
        utils.check_val_equal(perm.name, Permission.READ)
        utils.check_val_equal(perm.access, Access.ALLOW)
        utils.check_val_equal(perm.scope, Scope.MATCH)
        perm = PermissionSet("read-allow-match")  # new explicit format
        utils.check_val_equal(perm.name, Permission.READ)
        utils.check_val_equal(perm.access, Access.ALLOW)
        utils.check_val_equal(perm.scope, Scope.MATCH)
        perm = PermissionSet("read-allow-recursive")
        utils.check_val_equal(perm.name, Permission.READ)
        utils.check_val_equal(perm.access, Access.ALLOW)
        utils.check_val_equal(perm.scope, Scope.RECURSIVE)
        perm = PermissionSet("read-deny-match")
        utils.check_val_equal(perm.name, Permission.READ)
        utils.check_val_equal(perm.access, Access.DENY)
        utils.check_val_equal(perm.scope, Scope.MATCH)
        perm = PermissionSet(Permission.READ)
        utils.check_val_equal(perm.name, Permission.READ)
        utils.check_val_equal(perm.access, Access.ALLOW)
        utils.check_val_equal(perm.scope, Scope.RECURSIVE)
        perm = PermissionSet(Permission.WRITE, access="deny")
        utils.check_val_equal(perm.name, Permission.WRITE)
        utils.check_val_equal(perm.access, Access.DENY)
        utils.check_val_equal(perm.scope, Scope.RECURSIVE)
