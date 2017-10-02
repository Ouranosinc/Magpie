import os
curr_dir = os.path.dirname(__file__)+'/alembic.ini'
os.system('alembic -c {} upgrade heads'.format(curr_dir))