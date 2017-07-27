from magpie import *
import models


@view_config(route_name='users', request_method='POST')
def create_user(request):
    user_name = request.POST.get('user_name')
    email = request.POST.get('email')
    password = request.POST.get('password')
    group_name = request.POST.get('group_name')

    try:
        db = request.db
        new_user = models.User(user_name=user_name, email=email)
        new_user.set_password(password)
        new_user.regenerate_security_code()
        db.add(new_user)
        db.commit()

        group = GroupService.by_group_name(group_name, db_session=db)
        group_entry = models.UserGroup(group_id=group.id, user_id=new_user.id)
        db.add(group_entry)
        db.commit()
    except:
        raise HTTPConflict(detail='this user already exists')

    return HTTPCreated()


@view_config(route_name='users', request_method='GET')
def get_users(request):
    user_name_list = [user.user_name for user in models.User.all(db_session=request.db)]
    json_response = {'user_names': user_name_list}
    return HTTPOk(
        body=json.dumps(json_response),
        content_type='application/json'
    )


@view_config(route_name='user', request_method='GET')
def get_user(request):
    user_name = request.matchdict.get('user_name')
    try:
        db = request.db
        user = UserService.by_user_name(user_name, db_session=db)
        json_response = {'user_name': user.user_name,
                         'email': user.email,
                         'group_names': [group.group_name for group in user.groups]}
    except:
        raise HTTPNotFound(detail='User not found')

    return HTTPOk(
        body=json.dumps(json_response),
        content_type='application/json'
    )


@view_config(route_name='user', request_method='DELETE')
def delete_user(request):
    user_name = request.matchdict.get('user_name')
    try:
        db = request.db
        user = UserService.by_user_name(user_name, db_session=db)
        db.delete(user)
        db.commit()

    except:
        db.rollback()
        raise HTTPNotFound(detail="This user does not exist")

    return HTTPOk()


@view_config(route_name='user_groups', request_method='GET')
def get_user_groups(request):
    user_name = request.matchdict.get('user_name')
    try:
        db = request.db
        user = UserService.by_user_name(user_name, db_session=db)
        json_response = {'group_names': [group.group_name for group in user.groups]}
    except:
        db.rollback()
        raise HTTPNotFound(detail="This user does not exist")
    return HTTPOk(
        body=json.dumps(json_response),
        content_type='application/json'
    )

@view_config(route_name='user_group', request_method='POST')
def assign_user_group(request):
    user_name = request.matchdict.get('user_name')
    group_name = request.matchdict.get('group_name')
    db = request.db
    try:
        user = UserService.by_user_name(user_name, db_session=db)
        if user is None:
            raise HTTPNotFound(detail='user not found')
        cur_group = GroupService.by_group_name(group_name, db_session=db)
        if cur_group is None:
            raise HTTPNotFound(detail='group not found')
        new_user_group = models.UserGroup(group_id=cur_group.id, user_id=user.id)
        db.add(new_user_group)
        db.commit()
    except:
        db.rollback()
        raise HTTPConflict(detail='this user already belongs to this group')

    return HTTPCreated()


@view_config(route_name='user_group', request_method='DELETE')
def delete_user_group(request, request_method='POST'):
    user_name = request.matchdict.get('user_name')
    group_name = request.matchdict.get('group_name')

    try:
        db = request.db
        user = UserService.by_user_name(user_name, db_session=db)
        if user is None:
            raise HTTPNotFound(detail='user not found')
        group = GroupService.by_group_name(group_name, db_session=db)
        if group is None:
            raise HTTPNotFound(detail='group not found')
        db.query(models.UserGroup)\
            .filter(models.UserGroup.user_id == user.id)\
            .filter(models.UserGroup.group_id == group.id)\
            .delete()
    except:
        db.rollback()
        raise HTTPConflict(detail='this user does not belong to this group')

    return HTTPOk()


