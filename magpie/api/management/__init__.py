def includeme(config):
    config.include('api.management.group')
    config.include('api.management.user')
    config.include('api.management.service')
    config.include('api.management.resource')
