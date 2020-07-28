<%inherit file="ui.home:templates/template.mako"/>

<%block name="breadcrumb">
<li><a href="${request.route_url('home')}">Home</a></li>
<li><a href="${request.route_url('view_users')}">Users</a></li>
</%block>

<h1>Users</h1>

<button class="img-button theme" type="button" onclick="location.href='${request.route_url('add_user')}'">
    <img src="${request.static_url('magpie.ui.home:static/add.png')}" alt="">
    Add User
</button>


<table class="simple-list">
<thead class="theme">
<tr>
    <th>User</th>
    <th>Action</th>
</tr>
</thead>
<tbody>
%for i, user in enumerate(users):
<form action="${request.path}" method="post">
%if i % 2:
<tr class="list-row-even">
%else:
<tr class="list-row-odd">
%endif
    <td><input type="hidden" value=${user} name="user_name">${user}</td>
    <td style="white-space: nowrap">
        <input type="submit" value="Edit" name="edit" class="button theme">
        <input type="submit" value="Delete" name="delete" class="button delete">
    </td>
</tr>
</form>
%endfor
</tbody>
</table>
