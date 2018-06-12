import logging
logger = logging.getLogger(__name__)


def includeme(config):
    logger.info('Adding api ...')
    config.add_route('api', '/api')
    config.add_static_view('swagger-ui', 'swagger-ui', cache_max_age=3600)
    config.scan()
