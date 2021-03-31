<%inherit file="magpie.ui.home:templates/template.mako"/>

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
    <th>Status</th>
    <th>Action</th>
</tr>
</thead>
<tbody>
%for i, user_name in enumerate(users):
    <form action="${request.path}" method="post">
        %if i % 2:
        <tr class="list-row-even">
        %else:
        <tr class="list-row-odd">
        %endif
            <td><input type="hidden" value="${user_name}" name="user_name">${user_name}</td>
            <td>
                %if user_name in users_with_error:
                    <img title="User account status has an issue." class="icon-warning" alt="WARNING"
                         src="${request.static_url('magpie.ui.home:static/exclamation-triangle.png')}"/>
                %else:
                    <img title="User account status is valid." class="icon-info" alt="OK"
                         src="${request.static_url('magpie.ui.home:static/checkmark-circle.png')}"/>
                %endif
            </td>
            <td style="white-space: nowrap">
                <input type="submit" value="Edit" name="edit" class="button theme">
                <input value="Delete" name="delete"
                    %if user_name in MAGPIE_FIXED_USERS:
                       type="button" class="button delete disabled" disabled
                    %else:
                       type="submit" class="button delete"
                    %endif
                >
            </td>
        </tr>
    </form>
%endfor
</tbody>
</table>
