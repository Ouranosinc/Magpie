from authomatic.providers import oauth2


class GitHub(oauth2.GitHub):
    # Original authomatic github implementation fails
    # because returned response location doesn't contain the
    # auth session state, which fails the whole transaction.
    # Removing CSRF protection bypasses the state validation.
    supports_csrf_protection = False


PROVIDER_ID_MAP = [GitHub]
