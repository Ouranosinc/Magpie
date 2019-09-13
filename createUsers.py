#!/usr/bin/env python3

import random
import requests
import string
import sys

email_list = sys.argv[1:]
users = []
for i in range(len(email_list)):
    users.append({'email': email_list[i]})
    users[i]['user_name'] = email_list[i].split('@')[0]
    # generate a password made of 8 random alphanumeric characters
    users[i]['password'] = "".join(random.choice(string.ascii_letters + string.digits) for _ in range(8))

password_list = []

# login
session = requests.Session()
print(session.post("http://192.168.99.201:2001/magpie/signin", data={'user_name': 'admin', 'password': 'admin', 'provider_name': 'ziggurat'}))

for i in range(len(users)):
    # submit new users
    data = {'user_name': users[i]['user_name'],
            'email': users[i]['email'],
            'password': users[i]['password'],
            'group_name': 'users',
            'create': 'Add User'}
    print(session.post("http://192.168.99.201:2001/magpie/ui/users/add", data = data))

session.get("http://192.168.99.201:2001/magpie/signout")

# test each users with a login
for i in range(len(users)):
    response = session.post("http://192.168.99.201:2001/magpie/signin", data={'user_name': users[i]['user_name'], 'password': users[i]['password'], 'provider_name': 'ziggurat'})
    print(response)
    # return list of users/pwds
    print(users[i]['user_name'])
    print(users[i]['password'])

#TODO : erreur si crée un compte qui existe déjà, va générer un password qui fonctionne pas
#TODO : vérifier avec le site web public
#TODO : retourner dans un fichier?