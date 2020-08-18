<%inherit file="ui.management:templates/tree_scripts.mako"/>
<%namespace name="tree" file="ui.management:templates/tree_scripts.mako"/>

<%def name="render_item(key, value, level)">
    <input type="hidden" value="" name="edit_permissions">
    %for perm in permissions:
        <div class="perm-checkbox">
            % if perm in value['permission_names']:
            <label>
            <input type="checkbox" value="${perm}" name="permission"
                   onchange="document.getElementById('resource_${value['id']}_${value.get('remote_id', '')}').submit()"
                   checked>
            </label>
            % else:
            <label>
            <input type="checkbox" value="${perm}" name="permission"
                   onchange="document.getElementById('resource_${value['id']}_${value.get('remote_id', '')}').submit()">
            </label>
            % endif
        </div>
    %endfor
    % if not value.get('matches_remote', True):
        <div class="tree-button">
            <input type="submit" class="button-warning" value="Clean" name="clean_resource">
        </div>
        <p class="tree-item-message">
            <img title="This resource is absent from the remote server." class="icon-warning"
                 src="${request.static_url('magpie.ui.home:static/exclamation-triangle.png')}" alt="WARNING" />
        </p>
    % endif
    % if level == 0:
        <div class="tree-button">
            <input type="submit" class="tree-button goto-service theme" value="Edit Service" name="goto_service">
        </div>
    % endif
</%def>


<%block name="breadcrumb">
<li><a href="${request.route_url('home')}">
    Home</a></li>
<li><a href="${request.route_url('view_groups')}">
    Groups</a></li>
<li><a href="${request.route_url('edit_group', group_name=group_name, cur_svc_type=cur_svc_type)}">
    Group [${group_name}]</a></li>
</%block>

<h1>Edit Group: [${group_name}]</h1>


<h3>Group Information</h3>

<div class="panel-box">
    <div class="panel-heading theme">
        <form id="delete_group" action="${request.path}" method="post">
            <span class="panel-title">Group: </span>
            <span class="panel-value">[${group_name}]</span>
            <span class="panel-heading-button">
                <input type="submit" value="Delete" name="delete" class="button delete">
            </span>
        </form>
    </div>
    <div class="panel-body">
        <div class="panel-box">
            <div class="panel-heading subsection">
                <div class="panel-title">Details</div>
            </div>
            <div>
                <form id="edit_name" action="${request.path}" method="post">
                    <p class="panel-line">
                        <span class="panel-entry">Name: </span>
                        %if edit_mode == "edit_group_name" and group_name not in MAGPIE_FIXED_GROUP_EDITS:
                            <label>
                            <input type="text" value="${group_name}" placeholder="group name" name="new_group_name"
                                   id="input_group_name" onkeyup="adjustWidth('input_group_name')">
                            <input type="submit" value="Save" name="save_group_name" class="button theme">
                            <input type="submit" value="Cancel" name="no_edit" class="button cancel">
                            </label>
                        %else:
                            <label>
                            <span class="panel-value">${group_name}</span>
                            %if group_name not in MAGPIE_FIXED_GROUP_EDITS:
                            <input type="submit" value="Edit" name="edit_group_name" class="button theme">
                            %endif
                            </label>
                        %endif
                    </p>
                </form>
                <form id="edit_description" action="${request.path}" method="post">
                    <p class="panel-line">
                        <span class="panel-entry">Name: </span>
                        %if edit_mode == "edit_description" and group_name not in MAGPIE_FIXED_GROUP_EDITS:
                            <label>
                            <input type="text" value="${description}" placeholder="description" name="new_description"
                                   id="input_description" onkeyup="adjustWidth('input_description')">
                            <input type="submit" value="Save" name="save_description" class="button theme">
                            <input type="submit" value="Cancel" name="no_edit" class="button cancel">
                            </label>
                        %else:
                            <label>
                            <span class="panel-value">
                                %if description:
                                    ${description}
                                %else:
                                    n/a
                                %endif
                            </span>
                            %if group_name not in MAGPIE_FIXED_GROUP_EDITS:
                            <input type="submit" value="Edit" name="edit_description" class="button theme">
                            %endif
                            </label>
                        %endif
                    </p>
                </form>
                <form id="edit_discoverable" action="${request.path}" method="post">
                    <p class="panel-line">
                        <span class="panel-entry">Name: </span>
                        <label>
                        <input type="checkbox" value="${discoverable}" name="new_discoverable"
                               id="input_discoverable"
                            %if discoverable:
                               checked
                            %endif
                            %if group_name in MAGPIE_FIXED_GROUP_EDITS:
                               disabled
                            %else:
                               onchange="document.getElementById('edit_discoverable').submit()"
                            %endif
                        >
                        </label>
                    </p>
                </form>
            </div>
        </div>
    </div>
</div>

<h3>Members</h3>

<form id="edit_members" action="${request.path}" method="post">
<table class="simple-list">
%for user in users:
<tr>
    <td>
        <label>
        <input type="checkbox" value="${user}" name="member"
            %if user in members:
               checked
            %endif
            %if group_name in MAGPIE_FIXED_GROUP_MEMBERSHIPS:
               disabled
            %else:
               onchange="document.getElementById('edit_members').submit()"
            %endif
        >
        ${user}
        </label>
    </td>
</tr>
%endfor
</table>
</form>

<h3>Permissions</h3>

<div class="tabs-panel">

    %for svc_type in svc_types:
        % if cur_svc_type == svc_type:
            <a class="current-tab"
               href="${request.route_url('edit_group', group_name=group_name, cur_svc_type=svc_type)}">${svc_type}</a>
        % else:
            <a class="tab theme"
               href="${request.route_url('edit_group', group_name=group_name, cur_svc_type=svc_type)}">${svc_type}</a>
        % endif
    %endfor

    <div class="current-tab-panel">
        <div class="clear"></div>
        %if error_message:
            <div class="alert alert-danger alert-visible">${error_message}</div>
        %endif
        <form id="sync_info" action="${request.path}" method="post">
            <p class="panel-line">
                <span class="panel-entry">Last synchronization with remote services: </span>
                %if sync_implemented:
                    <span class="panel-value">${last_sync} </span>
                    <input type="submit" value="Sync now" name="force_sync" class="button theme">
                %else:
                    <span class="panel-value">Not implemented for this service type.</span>
                %endif
            </p>
            %if ids_to_clean and not out_of_sync:
                <p class="panel-line">
                    <span class="panel-entry">Note: </span>
                    <span class="panel-value">Some resources are absent from the remote server </span>
                    <input type="hidden" value="${ids_to_clean}" name="ids_to_clean">
                    <input type="submit" class="button-warning" value="Clean all" name="clean_all">
                </p>
            %endif
        </form>

        <div class="tree-header">
            <div class="tree-item">Resources</div>
            %for perm in permissions:
                <div class="perm-title">${perm}</div>
            %endfor
        </div>
        <div class="tree">
            ${tree.render_tree(render_item, resources)}
        </div>
    </div>
</div>
