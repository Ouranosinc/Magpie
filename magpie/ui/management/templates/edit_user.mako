<%inherit file="ui.home:templates/template.mako"/>

<%block name="breadcrumb">
<li><a href="${request.route_url('home')}">Home</a></li>
<li><a href="${request.route_url('view_users')}">Users</a></li>
<li><a href="${request.route_url('edit_user', user_name=user_name)}">User ${user_name}</a></li>
</%block>

<h1>User ${user_name}</h1>

<h3>Member of</h3>

<form id="edit_membership" action="${request.path}" method="post">
<table>
%for group in groups:
<tr>
    % if group in own_groups:
        <td>
            <input type="checkbox" value="${group}" name="member" checked
                   onchange="document.getElementById('edit_membership').submit()">
            ${group}
        </td>
    % else:
        <td>
            <input type="checkbox" value="${group}" name="member"
                   onchange="document.getElementById('edit_membership').submit()">
            ${group}
        </td>
    % endif
</tr>
%endfor
</table>
</form>

</body>
</html>
