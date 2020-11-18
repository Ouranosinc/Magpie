import pytest
import unittest

from magpie import __meta__
from magpie.constants import get_constant
from tests import interfaces as ti, runner, utils


@runner.MAGPIE_TEST_LOCAL
@runner.MAGPIE_TEST_ADAPTER
@runner.MAGPIE_TEST_FUNCTIONAL
class TestServices(ti.SetupMagpieAdapter, ti.AdminTestCase, ti.BaseTestCase):
    __test__ = True

    @classmethod
    @utils.mock_get_settings
    def setUpClass(cls):
        cls.version = __meta__.__version__
        cls.app = utils.get_test_magpie_app(cls.settings)
        cls.grp = get_constant("MAGPIE_ADMIN_GROUP")
        cls.usr = get_constant("MAGPIE_TEST_ADMIN_USERNAME")
        cls.pwd = get_constant("MAGPIE_TEST_ADMIN_PASSWORD")
        cls.settings = cls.app.app.registry.settings
        cls.setup_adapter()

        cls.cookies = None
        cls.version = utils.TestSetup.get_Version(cls)
        cls.setup_admin()
        cls.headers, cls.cookies = utils.check_or_try_login_user(cls.app, cls.usr, cls.pwd, use_ui_form_submit=True)
        cls.require = "cannot run tests without logged in user with '{}' permissions".format(cls.grp)
        cls.check_requirements()

        # following will be wiped on setup
        cls.test_user_name = "unittest-service-user"
        cls.test_group_name = "unittest-service-group"

    def mock_request(self, *args, **kwargs):
        kwargs.update({"cookies": self.test_cookies, "headers": self.test_headers})
        return super(TestServices, self).mock_request(*args, **kwargs)

    @unittest.skip("impl")
    @pytest.mark.skip
    def test_unauthenticated_service_blocked(self):
        """
        Validate missing authentication token blocks access to the service if not publicly accessible.
        """
        raise NotImplementedError  # FIXME

    @unittest.skip("impl")
    @pytest.mark.skip
    def test_unauthenticated_resource_allowed(self):
        """
        Validate granted access to a resource specified as publicly accessible even without any authentication token.
        """
        raise NotImplementedError  # FIXME

    @unittest.skip("impl")
    @pytest.mark.skip
    def test_unknown_service(self):
        """
        Validate that unknown service-name is handled correctly.
        """
        raise NotImplementedError  # FIXME

    @unittest.skip("impl")
    @pytest.mark.skip
    def test_unknown_resource_under_service(self):
        """
        Evaluate use-case where requested resource when parsing the request corresponds to non-existing element.

        If the targeted resource does not exist in database, `Magpie` should still allow access if its closest
        available parent permission results into Allow/Recursive.

        If the closest parent permission permission is either Match-scoped or explicit Deny, access should be refused.
        """
        raise NotImplementedError  # FIXME
