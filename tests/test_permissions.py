import itertools
import unittest

from pyramid.security import ALL_PERMISSIONS, Allow, Deny
from ziggurat_foundations.permissions import PermissionTuple  # noqa

from magpie import __meta__, models
from magpie.permissions import Access, Permission, PermissionSet, PermissionType, Scope, format_permissions
from tests import runner, utils


class MockObject(object):
    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, property(lambda *_, **__: v))


@runner.MAGPIE_TEST_LOCAL
@runner.MAGPIE_TEST_UTILS
@runner.MAGPIE_TEST_PERMISSIONS
class TestPermissions(unittest.TestCase):
    def test_format_permissions_applied(self):
        """
        Validate that provided permission sets are formatted as intended, with both implicit and explicit variants, and
        with both name strings and detailed JSON objects.
        """
        utils.warn_version(self, "permission format validation", "3.0", test_version=__meta__.__version__, skip=True)

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

        perm_type = PermissionType.DIRECT  # anything else than 'allowed' to only get 'applied' permissions
        format_perms = format_permissions(any_perms, perm_type)
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
            PermissionSet(Permission.GET_CAPABILITIES, Access.ALLOW, Scope.RECURSIVE, perm_type).json(),
            PermissionSet(Permission.GET_FEATURE, Access.ALLOW, Scope.RECURSIVE, perm_type).json(),
            PermissionSet(Permission.GET_LEGEND_GRAPHIC, Access.DENY, Scope.MATCH, perm_type).json(),
            PermissionSet(Permission.GET_MAP, Access.DENY, Scope.RECURSIVE, perm_type).json(),
            PermissionSet(Permission.GET_METADATA, Access.DENY, Scope.RECURSIVE, perm_type).json(),
            PermissionSet(Permission.READ, Access.ALLOW, Scope.RECURSIVE, perm_type).json(),
            PermissionSet(Permission.WRITE, Access.ALLOW, Scope.MATCH, perm_type).json(),
        ]
        utils.check_all_equal(format_perms["permission_names"], expect_names, any_order=False)
        utils.check_all_equal(format_perms["permissions"], expect_perms, any_order=False)

    def test_format_permissions_allowed(self):
        """
        Validate that formats are also respected, but with additional auto-expansion of all *modifier* combinations on
        permission names when requesting :attr:`PermissionType.ALLOWED` permissions.

        .. seealso::
            :meth:`test_format_permissions_applied`
        """
        utils.warn_version(self, "permission format validation", "3.0", test_version=__meta__.__version__, skip=True)

        # add duplicates with extra modifiers only to test removal
        # provide in random order to validate proper sorting
        # use multiple permission implementation to validate they are still handled
        test_perms = [
            PermissionSet(Permission.READ, Access.DENY, Scope.RECURSIVE),
            PermissionSet(Permission.READ, Access.DENY, Scope.MATCH),
            PermissionSet(Permission.READ, Access.ALLOW, Scope.RECURSIVE),
            PermissionSet(Permission.READ, Access.ALLOW, Scope.MATCH),
            Permission.READ,
            "write-match",  # old implicit format
            Permission.WRITE,
        ]
        format_perms = format_permissions(test_perms, PermissionType.ALLOWED)
        expect_names = [
            Permission.READ.value + "-" + Scope.MATCH.value,
            str(PermissionSet(Permission.READ, Access.ALLOW, Scope.MATCH)),
            Permission.READ.value,
            str(PermissionSet(Permission.READ, Access.ALLOW, Scope.RECURSIVE)),
            # no implicit name for denied
            str(PermissionSet(Permission.READ, Access.DENY, Scope.MATCH)),
            str(PermissionSet(Permission.READ, Access.DENY, Scope.RECURSIVE)),
            Permission.WRITE.value + "-" + Scope.MATCH.value,
            str(PermissionSet(Permission.WRITE, Access.ALLOW, Scope.MATCH)),
            Permission.WRITE.value,
            str(PermissionSet(Permission.WRITE, Access.ALLOW, Scope.RECURSIVE)),
            # no implicit name for denied
            str(PermissionSet(Permission.WRITE, Access.DENY, Scope.MATCH)),
            str(PermissionSet(Permission.WRITE, Access.DENY, Scope.RECURSIVE)),
        ]
        expect_perms = [
            PermissionSet(Permission.READ, Access.ALLOW, Scope.MATCH, PermissionType.ALLOWED).json(),
            PermissionSet(Permission.READ, Access.ALLOW, Scope.RECURSIVE, PermissionType.ALLOWED).json(),
            PermissionSet(Permission.READ, Access.DENY, Scope.MATCH, PermissionType.ALLOWED).json(),
            PermissionSet(Permission.READ, Access.DENY, Scope.RECURSIVE, PermissionType.ALLOWED).json(),
            PermissionSet(Permission.WRITE, Access.ALLOW, Scope.MATCH, PermissionType.ALLOWED).json(),
            PermissionSet(Permission.WRITE, Access.ALLOW, Scope.RECURSIVE, PermissionType.ALLOWED).json(),
            PermissionSet(Permission.WRITE, Access.DENY, Scope.MATCH, PermissionType.ALLOWED).json(),
            PermissionSet(Permission.WRITE, Access.DENY, Scope.RECURSIVE, PermissionType.ALLOWED).json(),
        ]
        utils.check_all_equal(format_perms["permission_names"], expect_names, any_order=False)
        utils.check_all_equal(format_perms["permissions"], expect_perms, any_order=False)

    def test_permission_convert_from_string(self):
        """
        Conversion by implicit/explicit name.

        Validate various implicit conversion of permission name string to explicit definition.
        """
        utils.warn_version(self, "permission set conversion", "3.0", test_version=__meta__.__version__, skip=True)

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

    def test_permission_convert_from_enum(self):
        """
        Conversion by enum values.

        Validate various implicit conversion of permission name string to explicit definition.
        """
        utils.warn_version(self, "permission set conversion", "3.0", test_version=__meta__.__version__, skip=True)

        perm = PermissionSet(Permission.READ)
        utils.check_val_equal(perm.name, Permission.READ)
        utils.check_val_equal(perm.access, Access.ALLOW)
        utils.check_val_equal(perm.scope, Scope.RECURSIVE)
        perm = PermissionSet(Permission.WRITE, access="deny")
        utils.check_val_equal(perm.name, Permission.WRITE)
        utils.check_val_equal(perm.access, Access.DENY)
        utils.check_val_equal(perm.scope, Scope.RECURSIVE)

    def test_permission_convert_from_json(self):
        """
        Conversion by JSON definition.

        Validate various implicit conversion of permission JSON definition.
        """
        utils.warn_version(self, "permission set conversion", "3.0", test_version=__meta__.__version__, skip=True)

        perm = PermissionSet({"name": Permission.WRITE, "access": Access.DENY, "scope": Scope.MATCH})
        utils.check_val_equal(perm.name, Permission.WRITE)
        utils.check_val_equal(perm.access, Access.DENY)
        utils.check_val_equal(perm.scope, Scope.MATCH)
        perm = PermissionSet({"name": Permission.WRITE.value, "access": Access.DENY.value, "scope": Scope.MATCH.value})
        utils.check_val_equal(perm.name, Permission.WRITE)
        utils.check_val_equal(perm.access, Access.DENY)
        utils.check_val_equal(perm.scope, Scope.MATCH)

    def test_permission_convert_from_tuple(self):
        """
        Conversion from Ziggurat :class:`PermissionTuple` object.

        Validate various implicit conversion of permission elements to explicit definition.
        """
        utils.warn_version(self, "permission set conversion", "3.0", test_version=__meta__.__version__, skip=True)

        perm = PermissionSet(PermissionTuple("user-name", "write-deny-match", "user",  # important: perm-name & type
                                             "group_id", "resource_id", "owner", "allowed"))  # these doesn't matter
        utils.check_val_equal(perm.name, Permission.WRITE)
        utils.check_val_equal(perm.access, Access.DENY)
        utils.check_val_equal(perm.scope, Scope.MATCH)
        utils.check_val_equal(perm.type, PermissionType.DIRECT, msg="PermissionTuple should also help identify type")
        perm = PermissionSet(PermissionTuple("user-name", "write-deny-match", "group",  # important: perm-name & type
                                             "group_id", "resource_id", "owner", "allowed"))  # these doesn't matter
        utils.check_val_equal(perm.name, Permission.WRITE)
        utils.check_val_equal(perm.access, Access.DENY)
        utils.check_val_equal(perm.scope, Scope.MATCH)
        utils.check_val_equal(perm.type, PermissionType.INHERITED, msg="PermissionTuple should also help identify type")

    def test_permission_convert_from_acl(self):
        """
        Conversion from Pyramid ACL definition.

        Validate various implicit conversion of permission elements to explicit definition.
        """
        utils.warn_version(self, "permission set conversion", "3.0", test_version=__meta__.__version__, skip=True)

        perm = PermissionSet((Allow, 1, "write-deny-match"))
        utils.check_val_equal(perm.name, Permission.WRITE)
        utils.check_val_equal(perm.access, Access.DENY, msg="Explicit permission name prioritized over ACL access")
        utils.check_val_equal(perm.scope, Scope.MATCH)
        utils.check_val_equal(perm.type, PermissionType.DIRECT, msg="Should infer direct from user ID.")
        perm = PermissionSet((Deny, "group:1", "read"))
        utils.check_val_equal(perm.name, Permission.READ)
        utils.check_val_equal(perm.access, Access.DENY)
        utils.check_val_equal(perm.scope, Scope.RECURSIVE)
        utils.check_val_equal(perm.type, PermissionType.INHERITED, msg="Should infer inherited from group specifier.")
        utils.check_raises(lambda: PermissionSet((Allow, "group:1", ALL_PERMISSIONS)), TypeError,
                           msg="Don't allow any object that makes the permission name not explicitly defined.")

    def test_compare_and_sort_operations(self):
        perm_ram = PermissionSet(Permission.READ, Access.ALLOW, Scope.MATCH)
        perm_rar = PermissionSet(Permission.READ, Access.ALLOW, Scope.RECURSIVE)
        perm_rdm = PermissionSet(Permission.READ, Access.DENY, Scope.MATCH)
        perm_rdr = PermissionSet(Permission.READ, Access.DENY, Scope.RECURSIVE)
        perm_wam = PermissionSet(Permission.WRITE, Access.ALLOW, Scope.MATCH)
        perm_war = PermissionSet(Permission.WRITE, Access.ALLOW, Scope.RECURSIVE)
        perm_wdm = PermissionSet(Permission.WRITE, Access.DENY, Scope.MATCH)
        perm_wdr = PermissionSet(Permission.WRITE, Access.DENY, Scope.RECURSIVE)
        perm_sorted = [perm_ram, perm_rar, perm_rdm, perm_rdr, perm_wam, perm_war, perm_wdm, perm_wdr]
        perm_random = [perm_rdr, perm_wam, perm_wdm, perm_rar, perm_war, perm_ram, perm_wdr, perm_rdm]

        utils.check_val_equal(perm_rar, Permission.READ, msg="Should be equal because of defaults and name conversion")
        utils.check_val_not_equal(perm_rar, Permission.WRITE, msg="Not equal because of mismatch name")
        utils.check_val_equal(perm_rar, perm_rar.json(), msg="Pre-convert any known representation before equal check")

        utils.check_all_equal(list(sorted(perm_random)), perm_sorted, any_order=False)

        # cannot sort elements with other type representations although 'PermissionSet' can, because they don't know it
        # (ie: str.__lt__ and dict.__ls__ could be called with 'other' being 'PermissionSet' depending on random order)
        # can still do the individual compares though if the reference object is 'PermissionSet' and other is anything
        utils.check_val_equal(perm_sorted[0] < perm_sorted[1], True)
        utils.check_val_equal(perm_sorted[0] < perm_sorted[1].json(), True)
        utils.check_val_equal(perm_sorted[0] < perm_sorted[1].implicit_permission, True)
        utils.check_val_equal(perm_sorted[0] < perm_sorted[1].explicit_permission, True)
        utils.check_val_equal(perm_sorted[0] > perm_sorted[1], False)
        utils.check_val_equal(perm_sorted[0] > perm_sorted[1].json(), False)
        utils.check_val_equal(perm_sorted[0] > perm_sorted[1].implicit_permission, False)
        utils.check_val_equal(perm_sorted[0] > perm_sorted[1].explicit_permission, False)

        # validate similarity comparison with inplace conversion at the same time
        for perm_1, perm_2 in itertools.product(perm_sorted[0:4], perm_sorted[0:4]):
            utils.check_val_equal(perm_1.like(perm_2.json()), True, msg="Expected {!r} ~ {!r}".format(perm_1, perm_2))
        for perm_1, perm_2 in itertools.product(perm_sorted[0:4], perm_sorted[4:8]):
            utils.check_val_equal(perm_1.like(perm_2.json()), False, msg="Expected {!r} !~ {!r}".format(perm_1, perm_2))

    def test_permission_resolve_raised_invalid(self):
        """
        Ensure that resolution with completely invalid/impossible cases are raised instead of failing silently.
        """
        perm_r = PermissionSet(Permission.READ, Access.ALLOW, Scope.RECURSIVE, PermissionType.DIRECT)
        res1 = MockObject(resource_name="mock-resource1", resource_id=987)
        res2 = MockObject(resource_name="mock-resource2", resource_id=101)
        usr = MockObject(user_name="mock-user", user_id=123)
        grp = MockObject(group_name="mock-group", user_id=456)
        usr_tup = PermissionTuple(usr, perm_r.explicit_permission, "user", None, res1, False, True)
        usr_perm = PermissionSet(usr_tup)

        # two same user permissions of identical name cannot exist
        utils.check_raises(lambda: PermissionSet.resolve(usr_perm, usr_perm), ValueError,
                           msg="Should raise permissions corresponding by name and user, cannot exist simultaneously.")

        # various values that are valid to create 'PermissionSet', but insufficient for resolution
        valid_only_for_repr = [
            Permission.READ.value,
            Permission.READ.value + "-" + Scope.MATCH.value,
            Permission.READ.value + "-" + Access.ALLOW.value + "-" + Scope.MATCH.value,
            {"name": Permission.READ, "access": Access.DENY, "scope": Scope.MATCH},
            PermissionSet(Permission.READ.value, Access.ALLOW.value, Scope.MATCH.value)  # missing 'perm_tuple'
        ]
        for perm1, perm2 in itertools.permutations(valid_only_for_repr, 2):
            utils.check_raises(lambda: PermissionSet.resolve(perm1, perm2), ValueError,
                               msg="Permission that do not provide comparison elements for resolution must be raised, "
                                   "although they are normally valid for simple permission representation.")

        # valid user and group tuples (both provide tuples, point to same resource, and don't refer to same user-perm)
        # but mismatching permission names
        perm_w = PermissionSet(Permission.WRITE, Access.ALLOW, Scope.RECURSIVE, PermissionType.DIRECT)
        grp_tup = PermissionTuple(usr, perm_w.explicit_permission, "group", grp, res1, False, True)
        grp_perm = PermissionSet(grp_tup)
        utils.check_raises(lambda: PermissionSet.resolve(usr_perm, grp_perm), ValueError,
                           msg="Mismatching permission names should be raised as they cannot be resolved together.")

        # same perm name (read), both tuple provided, not both user-perms, but not referring to same resource
        grp_tup = PermissionTuple(usr, perm_r.explicit_permission, "group", grp, res2, False, True)
        grp_perm = PermissionSet(grp_tup)
        utils.check_raises(lambda: PermissionSet.resolve(usr_perm, grp_perm), ValueError,
                           msg="Mismatching resources should be raised as they cannot be resolved together.")
        utils.check_no_raise(lambda: PermissionSet.resolve(usr_perm, grp_perm, context=PermissionType.EFFECTIVE),
                             msg="Mismatching resources should resolved when requested explicitly (effective).")
