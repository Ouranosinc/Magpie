<%inherit file="ui.home:templates/template.mako"/>
<%inherit file="ui.management:templates/tree_scripts.mako"/>
<%namespace name="tree" file="ui.management:templates/tree_scripts.mako"/>

<%def name="render_item(key, value, level)">
    %for perm in permissions:
        % if perm in value['permission_names']:
            <div class="perm_checkbox">
                <input type="checkbox" value="${perm}" name="permission"
                       onchange="document.getElementById('resource_${value['id']}').submit()" checked>
           </div>
        % else:
            <div class="perm_checkbox">
                <input type="checkbox" value="${perm}" name="permission"
                       onchange="document.getElementById('resource_${value['id']}').submit()">
            </div>
        % endif
    %endfor
    % if level == 0:
        <div class="tree_button">
            <input type="submit" class="tree_button goto_service" value="Edit Service" name="goto_service">
        </div>
    % endif
</%def>


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
        </div>
        <div class="panel_body">
            <div class="panel_box">
                <div class="panel_heading">
                    <div class="panel_title">Details</div>
                </div>
                <div>
                    <p class="panel_line">
                        <span class="panel_entry">Username: </span>
                        %if edit_mode == 'edit_username':
                            <input type="text" value="${user_name}" name="new_user_name"
                                   id="input_username" onkeyup="adjustWidth('input_name')">
                            <input type="submit" value="Save" name="save_username">
                            <input type="submit" value="Cancel" name="no_edit">
                        %else:
                            <span class="panel_value">${user_name}</span>
                            <input type="submit" value="Edit" name="edit_username">
                        %endif
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
                            <input type="text" value="${email}" name="new_user_email"
                                   id="input_email" onkeyup="adjustWidth('input_url')">
                            <input type="submit" value="Save" name="save_email">
                            <input type="submit" value="Cancel" name="no_edit">
                        %else:
                            <span class="panel_value">${email}</span>
                            <input type="submit" value="Edit" name="edit_email">
                        %endif
                    </p>
                </div>
            </div>
        </div>
    </form>
</div>


<h3>Groups Membership</h3>

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

<h3>Permissions</h3>

<div class="tabs_panel">

    %for svc_type in svc_types:
        % if cur_svc_type == svc_type:
            <a class="current_tab" href="${request.route_url('edit_users', user_name=user_name, cur_svc_type=svc_type)}">${svc_type}</a>
        % else:
            <a class="tab" href="${request.route_url('edit_users', user_name=user_name, cur_svc_type=svc_type)}">${svc_type}</a>
        % endif
    %endfor

    <div class="current_tab_panel">
        <div class="clear"/>
        <div class="tree_header">
        <div class="tree_item">Resources</div>
        %for perm in permissions:
            <div class="perm_title">${perm}</div>
        %endfor
        </div>
        <div class="tree">
            ${tree.render_tree(render_item, resources)}
        </div>
    </div>
</div>
