from service.resource import *
from service.service import *

def includeme(config):
    config.include('management.group')
    config.include('management.user')
    config.include('management.service')
