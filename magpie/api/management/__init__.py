def includeme(config):
    config.include('magpie.api.management.group')
    config.include('magpie.api.management.user')
    config.include('magpie.api.management.service')
    config.include('magpie.api.management.resource')
