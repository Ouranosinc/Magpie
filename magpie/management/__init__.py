def includeme(config):
    config.include('management.group')
    config.include('management.user')
    config.include('management.service')
    config.include('management.resource')
