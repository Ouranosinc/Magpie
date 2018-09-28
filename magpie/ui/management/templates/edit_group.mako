<%inherit file="ui.management:templates/tree_scripts.mako"/>
<%namespace name="tree" file="ui.management:templates/tree_scripts.mako"/>

<%def name="render_item(key, value, level)">
    <input type="hidden" value="" name="edit_permissions">
    %for perm in permissions:
        <div class="perm_checkbox">
            % if perm in value['permission_names']:
            <input type="checkbox" value="${perm}" name="permission"
                   onchange="document.getElementById('resource_${value['id']}_${value.get('remote_id', '')}').submit()" checked>
            % else:
            <input type="checkbox" value="${perm}" name="permission"
                   onchange="document.getElementById('resource_${value['id']}_${value.get('remote_id', '')}').submit()">
            % endif
        </div>
    %endfor
    % if not value.get('matches_remote', True):
        <div class="tree_button">
            <input type="submit" class="button warning" value="Clean" name="clean_resource">
        </div>
        <p class="tree_item_message">
            <img title="This resource is absent from the remote server."
                 src="${request.static_url('magpie.ui.home:static/warning_exclamation_orange.png')}" />
        </p>
    % endif
    % if level == 0:
        <div class="tree_button">
            <input type="submit" class="tree_button goto_service" value="Edit Service" name="goto_service">
        </div>
    % endif
</%def>


<%block name="breadcrumb">
<li><a href="${request.route_url('home')}">Home</a></li>
<li><a href="${request.route_url('view_groups')}">Groups</a></li>
<li><a href="${request.route_url('edit_group', group_name=group_name, cur_svc_type=cur_svc_type)}">Group ${group_name}</a></li>
</%block>

<h1>Edit Group: ${group_name}</h1>


<h3>Group Information</h3>

<div class="panel_box">
    <form id="edit_info" action="${request.path}" method="post">
        <div class="panel_heading">
            <span class="panel_title">Group: </span>
            <span class="panel_value">${group_name}</span>
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
                        <span class="panel_entry">Name: </span>
                        %if edit_mode == 'edit_group_name':
                            <input type="text" value="${group_name}" name="new_group_name"
                                   id="input_group_name" onkeyup="adjustWidth('input_name')">
                            <input type="submit" value="Save" name="save_group_name">
                            <input type="submit" value="Cancel" name="no_edit">
                        %else:
                            <span class="panel_value">${group_name}</span>
                            <input type="submit" value="Edit" name="edit_group_name">
                        %endif
                    </p>
                </div>
            </div>
        </div>
    </form>
</div>

<h3>Members</h3>

<form id="edit_members" action="${request.path}" method="post">
<table>
%for user in users:
<tr>
    % if user in members:
    <td><input type="checkbox" value="${user}" name="member"
               onchange="document.getElementById('edit_members').submit()"checked>${user}</td>
    % else:
    <td><input type="checkbox" value="${user}" name="member"
               onchange="document.getElementById('edit_members').submit()">${user}</td>
    % endif
</tr>
%endfor
</table>
</form>

<h3>Permissions</h3>

<div class="tabs_panel">

    %for svc_type in svc_types:
        % if cur_svc_type == svc_type:
            <a class="current_tab" href="${request.route_url('edit_group', group_name=group_name, cur_svc_type=svc_type)}">${svc_type}</a>
        % else:
            <a class="tab" href="${request.route_url('edit_group', group_name=group_name, cur_svc_type=svc_type)}">${svc_type}</a>
        % endif
    %endfor

    <div class="current_tab_panel">
        <div class="clear"/>
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
