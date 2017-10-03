<%inherit file="ui.home:templates/template.mako"/>

<%block name="breadcrumb">
<li><a href="${request.route_url('home')}">Home</a></li>
<li><a href="${request.route_url('view_users')}">Users</a></li>
</%block>

<h1>Users</h1>

<button class="img_button" type="button" onclick="location.href='${request.route_url('add_user')}'">
    <img src="${request.static_url('ui.home:static/add.png')}">
    Add User
</button>


<table class="simple_list_table">
<tr>
    <th>User</th>
    <th>Action</th>
</tr>

%for user in users:
<form action="${request.path}" method="post">
<tr>
    <td><input type="hidden" value=${user} name="user_name">${user}</td>
    <td style="white-space: nowrap">
        <input type="submit" value="Edit" name="edit">
        <input type="submit" value="Delete" name="delete" class="delete_button">
    </td>
</tr>
</form>
%endfor
</table>
