import os
curr_dir = os.path.dirname(__file__)
if curr_dir == '':
    curr_dir = os.path.abspath('.')
alembic_ini = '{}/alembic.ini'.format(curr_dir)
os.system('alembic -c {} upgrade heads'.format(alembic_ini))
