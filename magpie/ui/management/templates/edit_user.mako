<%inherit file="ui.home:templates/template.mako"/>

<%block name="breadcrumb">
<li><a href="${request.route_url('home')}">Home</a></li>
<li><a href="${request.route_url('view_users')}">Users</a></li>
<li><a href="${request.route_url('edit_user', user_name=user_name)}">User ${user_name}</a></li>
</%block>

<h1>Edit User: ${user_name}</h1>

<h3>User Information</h3>


<form class="panel_box">
    <form id="edit_info" action="${request.path}" method="post">
        <div class="panel_heading">
            <span class="panel_title">User: </span>
            <span class="panel_value">${user_name}</span>
            <span class="panel_heading_button">
                <input type="submit" value="Delete" name="delete" class="button delete">
            </span>
        </div>
        <div class="panel_body">
            <div class="panel_box">
                <div class="panel_heading">
                    <div class="panel_title">Details</div>
                </div>
                <div>
                    <p class="panel_line">
                        <span class="panel_entry">Username: </span>
                        <a href="${user_name}" class="panel_value">${user_name}</a>
                    </p>
                    <p class="panel_line">
                        <span class="panel_entry">Password: </span>
                        %if edit_mode == 'edit_password':
                            <input type="text" value="" name="new_user_password"
                                   id="input_password" onkeyup="adjustWidth('input_name')">
                            <input type="submit" value="Save" name="save_password">
                            <input type="submit" value="Cancel" name="no_edit">
                        %else:
                            <span class="panel_value">***</span>
                            <input type="submit" value="Edit" name="edit_password">
                        %endif
                    </p>
                    <p class="panel_line">
                        <span class="panel_entry">Email: </span>
                        %if edit_mode == 'edit_email':
                            <input type="text" value="${user_email}" name="new_user_email"
                                   id="input_email" onkeyup="adjustWidth('input_url')">
                            <input type="submit" value="Save" name="save_email">
                            <input type="submit" value="Cancel" name="no_edit">
                        %else:
                            <a href="${user_email}" class="panel_value">${user_email}</a>
                            <input type="submit" value="Edit" name="edit_email">
                        %endif
                    </p>
                </div>
            </div>
        </div>
    </form>
</form>


<h3>User Groups Membership</h3>

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
