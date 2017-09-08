<h3>Manage User Group</h3>
<form action="${ request.path }" method="post">
     <table style="width:100%">
        <tr>
            <th> User Name :</th>
        %for user in users:
            <th><input type="radio" name="user_names" value="${user['user_name']}" />${user['user_name']} </th>
        %endfor
        </tr>
        <tr>
            <th> Group Name :</th>
        %for group in groups:
            <th><input type="checkbox" name="group_names" value="${group}" />${group}</th>
        %endfor
        </tr>
    </table>
    <input type="submit" value="Assign Group" name="assign">
</form>

<h3>Delete User</h3>
<form action="${ request.path }" method="post">
    %for user in users:
        <input type="radio" name="user_names" value="${user['user_name']}" />
        ${user['user_name']}, ${user['group_names']}, ${user['email']}
        <br />
    %endfor
    <input type="submit" value="Delete" name="delete">
</form>

<h3>Remove User from group</h3>
<form action="${ request.path }" method="post">
    %for user_name, group_names in user_groups_dict.iteritems():
        <input type="radio" name="user_name" value="${user_name}" />
        ${user_name}:
        %for group_name in group_names:
            <input type="checkbox" name="group_names" value="${group_name}" />${group_name}
        %endfor
        <br />
    %endfor
    <input type="submit" value="Delete user-group link" name="delete_user_groups">
</form>

