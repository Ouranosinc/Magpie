from magpie import *
import models

@view_config(route_name='groups', request_method='GET')
def get_groups(request):
    group_name_list = [group.group_name for group in models.Group.all(db_session=request.db)]
    json_response = {'group_names': group_name_list}
    return HTTPOk(
        body=json.dumps(json_response),
        content_type='application/json'
    )


@view_config(route_name='groups', request_method='POST')
def create_group(request):
    try:
        db = request.db
        group_name = request.POST.get('group_name')
        new_group = models.Group(group_name=group_name)
        db.add(new_group)
        db.commit()
    except:
        # Group already exist
        raise HTTPConflict(detail='This name already exists')

    return HTTPCreated()


@view_config(route_name='group', request_method='DELETE')
def delete_group(request):
    group_name = request.matchdict.get('group_name')
    try:
        db = request.db
        group = GroupService.by_group_name(group_name, db_session=db)
        db.delete(group)
        db.commit()

    except:
        raise HTTPNotFound(detail="This group does not exist")

    return HTTPOk()


@view_config(route_name='group_users', request_method='GET')
def get_group_users(request):
    group_name = request.matchdict.get('group_name')
    try:
        db = request.db
        group = GroupService.by_group_name(group_name, db_session=db)
        json_response = {'user_names': [user.user_name for user in group.users]}
    except:
        raise HTTPNotFound(detail="This group does not exist")

    return HTTPOk(
        body=json.dumps(json_response),
        content_type='application/json'
    )

