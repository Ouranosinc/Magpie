<%inherit file="ui.home:templates/template.mako"/>
<%inherit file="ui.management:templates/tree_scripts.mako"/>
<%namespace name="tree" file="ui.management:templates/tree_scripts.mako"/>

<%def name="render_item(key, value, level)">
    <input type="hidden" value="" name="edit_permissions">
    %for perm in permissions:
        % if perm in value['permission_names']:
            <div class="perm_checkbox">
                <label>
                <input type="checkbox" value="${perm}" name="permission"
                       onchange="document.getElementById('resource_${value['id']}_${value.get('remote_id', '')}').submit()"
                       checked
                    %if inherit_groups_permissions:
                        disabled
                    %endif
                >
                </label>
           </div>
        % else:
            <div class="perm_checkbox">
                <label>
                <input type="checkbox" value="${perm}" name="permission"
                       onchange="document.getElementById('resource_${value['id']}_${value.get('remote_id', '')}').submit()"
                    %if inherit_groups_permissions:
                        disabled
                    %endif
                >
                </label>
            </div>
        % endif
    %endfor
    % if not value.get('matches_remote', True):
        <div class="tree_button">
            <input type="submit" class="button warning" value="Clean" name="clean_resource">
        </div>
        <p class="tree_item_message">
            <img title="This resource is absent from the remote server."
                 src="${request.static_url('magpie.ui.home:static/warning_exclamation_orange.png')}" alt="WARNING" />
        </p>
    % endif
    % if level == 0:
        <div class="tree_button">
            <input type="submit" class="tree_button goto_service" value="Edit Service" name="goto_service">
        </div>
    % endif
</%def>


<%block name="breadcrumb">
<li><a href="${request.route_url('home')}">
    Home</a></li>
<li><a href="${request.route_url('view_users')}">
    Users</a></li>
<li><a href="${request.route_url('edit_user', user_name=user_name, cur_svc_type=cur_svc_type)}">
    User [${user_name}]</a></li>
</%block>

<h1>Edit User: ${user_name}</h1>

<h3>User Information</h3>


<div class="panel_box">
    <form id="delete_user" action="${request.path}" method="post">
        <div class="panel_heading">
            <span class="panel_title">User: </span>
            <span class="panel_value">${user_name}</span>
            <span class="panel_heading_button">
                <input type="submit" value="Delete" name="delete" class="button delete">
            </span>
        </div>
    </form>
    <div class="panel_body">
        <div class="panel_box">
            <div class="panel_heading">
                <div class="panel_title">Details</div>
            </div>
            <div>
                <form id="edit_username" action="${request.path}" method="post">
                    <p class="panel_line">
                        <span class="panel_entry">Username: </span>
                        %if edit_mode == 'edit_username':
                            <label>
                            <input type="text" value="${user_name}" name="new_user_name"
                                   id="input_username" onkeyup="adjustWidth('input_name')">
                            <input type="submit" value="Save" name="save_username">
                            <input type="submit" value="Cancel" name="no_edit">
                            </label>
                        %else:
                            <label>
                            <span class="panel_value">${user_name}</span>
                            <input type="submit" value="Edit" name="edit_username">
                            </label>
                        %endif
                    </p>
                </form>
                <form id="edit_password" action="${request.path}" method="post">
                    <p class="panel_line">
                        <span class="panel_entry">Password: </span>
                        %if edit_mode == 'edit_password':
                            <label>
                            <input type="text" value="" name="new_user_password"
                                   id="input_password" onkeyup="adjustWidth('input_name')">
                            <input type="submit" value="Save" name="save_password">
                            <input type="submit" value="Cancel" name="no_edit">
                            </label>
                        %else:
                            <label>
                            <span class="panel_value">***</span>
                            <input type="submit" value="Edit" name="edit_password">
                            </label>
                        %endif
                    </p>
                </form>
                <form id="edit_email" action="${request.path}" method="post">
                    <p class="panel_line">
                        <span class="panel_entry">Email: </span>
                        %if edit_mode == 'edit_email':
                            <label>
                            <input type="text" value="${email}" name="new_user_email"
                                   id="input_email" onkeyup="adjustWidth('input_url')">
                            <input type="submit" value="Save" name="save_email">
                            <input type="submit" value="Cancel" name="no_edit">
                            </label>
                        %else:
                            <label>
                            <span class="panel_value">${email}</span>
                            <input type="submit" value="Edit" name="edit_email">
                            </label>
                        %endif
                    </p>
                </form>
            </div>
        </div>
    </div>
</div>


<h3>Groups Membership</h3>

<form id="edit_membership" action="${request.path}" method="post">
    <input type="hidden" value="True" name="edit_group_membership"/>
    <table>
    %for group in groups:
    <tr>
        <td>
            <label>
            <input type="checkbox" value="${group}" name="member"
                %if group in own_groups:
                   checked
                %endif
                %if group in MAGPIE_FIXED_GROUP_MEMBERSHIPS:
                   disabled
                %else:
                   onchange="document.getElementById('edit_membership').submit()"
                %endif
               >
            ${group}
            </label>
        </td>
    </tr>
    %endfor
    </table>
</form>

<h3>Permissions</h3>

<form id="toggle_visible_perms" action="${request.path}" method="post">
    <label>
    <input type="checkbox" value="${inherit_groups_permissions}" name="toggle_inherit_groups_permissions"
           onchange="document.getElementById('toggle_visible_perms').submit()"
    %if inherit_groups_permissions:
        checked>
        <input type="hidden" value="False" name="inherit_groups_permissions"/>
    %else:
        >
        <input type="hidden" value="True" name="inherit_groups_permissions"/>
    %endif
    View inherited group permissions
    </label>
</form>

<div class="tabs_panel">

    %for svc_type in svc_types:
        % if cur_svc_type == svc_type:
            <a class="current_tab"
               href="${request.route_url('edit_user', user_name=user_name, cur_svc_type=svc_type)}">${svc_type}</a>
        % else:
            <a class="tab"
               href="${request.route_url('edit_user', user_name=user_name, cur_svc_type=svc_type)}">${svc_type}</a>
        % endif
    %endfor

    <div class="current_tab_panel">
        <div class="clear"></div>
        %if error_message:
            <div class="alert danger visible">${error_message}</div>
        %endif
        <form id="sync_info" action="${request.path}" method="post">
            <p class="panel_line">
                <span class="panel_entry">Last synchronization with remote services: </span>
                %if sync_implemented:
                    <span class="panel_value">${last_sync} </span>
                    <input type="submit" value="Sync now" name="force_sync">
                %else:
                    <span class="panel_value">Not implemented for this service type.</span>
                %endif
            </p>
            %if ids_to_clean and not out_of_sync:
                <p class="panel_line">
                    <span class="panel_entry">Note: </span>
                    <span class="panel_value">Some resources are absent from the remote server </span>
                    <input type="hidden" value="${ids_to_clean}" name="ids_to_clean">
                    <input type="submit" class="button warning" value="Clean all" name="clean_all">
                </p>
            %endif
        </form>
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
