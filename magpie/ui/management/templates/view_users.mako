<%inherit file="home:templates/template.mako"/>

<%block name="breadcrumb">
<li><a href="${request.route_url('home')}">Home</a></li>
<li><a href="${request.route_url('view_users')}">Users</a></li>
</%block>

<h1>Users</h1>

<button class="img_button" type="button" onclick="location.href='${request.route_url('add_user')}'">
    <img src="${request.static_url('home:static/add.png')}">
    Add User
</button>


<table simple_list_table="simple_list_table">

%for user in users:
<form action="${request.path}" method="post">
<tr>
    <td><input type="hidden" value=${user} name="user_name">${user}</td>
    <td><input type="submit" value="Delete" name="delete"></td>
    <td><input type="submit" value="Edit" name="edit"></td>
</tr>
</form>
%endfor
</table>
