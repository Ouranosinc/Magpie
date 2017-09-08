import logging
import requests
logger = logging.getLogger(__name__)


def add_template_data(request, data=None):
    all_data = data or {}
    logged_user = None
    if 'user_name' in request.session and request.session['user_name']:
        logged_user = request.session['user_name']
    else:
        # Make a cache of the user_name to avoid always making server requests about that
        magpie_url = request.registry.settings['magpie.url']
        session = requests.get(magpie_url + '/session', cookies=request.cookies)

        if session.status_code == 200:
            json_data = session.json()
            if json_data['authenticated']:
                request.session['user_name'] = json_data['user_name']
                logged_user = request.session['user_name']

    if logged_user:
        all_data.update({'logged_user': logged_user})
    return all_data


def includeme(config):

    logger.info('Adding home ...')
    config.add_route('home', '/')
    config.add_route('test', '/test')
    config.add_static_view('static', 'static', cache_max_age=3600)
    config.scan()
