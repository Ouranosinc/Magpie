<%inherit file="ui.home:templates/template.mako"/>

<%block name="breadcrumb">
<li><a href="${request.route_url('home')}">Home</a></li>
<li><a href="${request.route_url('view_users')}">Users</a></li>
<li><a href="${request.route_url('edit_user', user_name=user_name)}">User ${user_name}</a></li>
</%block>

<h1>Edit User: ${user_name}</h1>

<h3>User Information</h3>


<div class="panel_box">
    <form id="edit_info" action="${request.path}" method="post">
        <div class="panel_heading">
            <span class="panel_title">User: </span>
            <span class="panel_value">${user_name}</span>
            <span class="panel_heading_button">
                <input type="submit" value="Delete" name="delete" class="button delete">
            </span>
        </
        <div class="panel_body">
            <div class="panel_box">
                <div class="panel_heading">
                    <div class="panel_title">Details</div>
                </div>
                <div>
                    <p class="panel_line">
                        <span class="panel_entry">Name: </span>
                        %if edit_mode == 'edit_name':
                            <input type="text" value="${service_name}" name="new_svc_name"
                                   id="input_name" onkeyup="adjustWidth('input_name')">
                            <input type="submit" value="Save" name="save_name">
                            <input type="submit" value="Cancel" name="no_edit">
                        %else:
                            <span class="panel_value">${service_name}</span>
                            <input type="submit" value="Edit" name="edit_name">
                        %endif
                    </p>
                    <p class="panel_line">
                        <span class="panel_entry">Protected URL: </span>
                        %if edit_mode == 'edit_url':
                            <input type="text" value="${service_url}" name="new_svc_url"
                                   id="input_url" onkeyup="adjustWidth('input_url')">
                            <input type="submit" value="Save" name="save_url">
                            <input type="submit" value="Cancel" name="no_edit">
                        %else:
                            <a href="${service_url}" class="panel_value">${service_url}</a>
                            <input type="submit" value="Edit" name="edit_url">
                        %endif
                    </p>
                    <p class="panel_line">
                        <span class="panel_entry">Public URL: </span>
                        <a href="${public_url}" class="panel_value">${public_url}</a>
                    </p>
                    <p class="panel_line">
                        <span class="panel_entry">Type: </span>
                        <span class="label info">${cur_svc_type}</span>
                    </p>
                    <p class="panel_line">
                        <span class="panel_entry">Permissions: </span>
                        <span class="panel_value">${service_perm}</span>
                    </p>
                    <p class="panel_line">
                        <span class="panel_entry">ID: </span>
                        <span class="panel_value">${service_id}</span>
                    </p>


<h3>User Groups</h3>

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
