from pyramid.config import Configurator
from pyramid.session import SignedCookieSessionFactory


def main(global_settings, **settings):
    session_factory = SignedCookieSessionFactory(settings['auth.secret'])

    config = Configurator(
        settings=settings,
        session_factory=session_factory
    )

    config.include('pyramid_mako')
    config.include('magpie.ui')

    config.scan()
    return config.make_wsgi_app()


if __name__ == '__main__':
    settings = {
        'auth.secret': 'magpie',
        'magpie.url': 'http://localhost:2001',
        'pyramid.reload_templates': True
    }
    app = main({}, **settings)
    from wsgiref.simple_server import make_server

    server = make_server('0.0.0.0', 5003, app)
    server.serve_forever()
