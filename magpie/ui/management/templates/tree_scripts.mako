<%inherit file="magpie.ui.home:templates/template.mako"/>


<!-- renders a tree of nested service/resources using the provided item renderer function
     see 'tree_toggle.js' for toggling even
-->
<%def name="render_tree(item_renderer, tree, level=0)">
    <ul class="tree-level-${level}">
    %for key in tree:
        %if tree[key]["children"]:
        <li class="collapsible expanded">
        %else:
        <li class="no-child">
        %endif
            <div class="tree-line">
                <div class="tree-key">
                    ${tree[key].get('resource_display_name', key)}
                </div>
                <div class="tree-item">
                    ${item_renderer(key, tree[key], level)}
                </div>
            </div>
            <div class="clear"></div>
            %if tree[key]["children"]:
            ${render_tree(item_renderer, tree[key]["children"], level + 1)}
            %endif
        </li>
    %endfor
    </ul>
</%def>


<!-- renderer of specific tree resources with applicable permissions (under a given service-type) -->
<%def name="render_resource_permission_tree(resources, permissions)">
    <form id="resources_permissions" action="${request.path}" method="post">
        <input type="submit" name="edit_permissions" value="Apply" title="Apply the permission changes"
            %if inherit_groups_permissions:
                disabled
                class="button theme equal-width disabled"
            %else:
                class="button theme equal-width"
            %endif
        >
        <div class="tree-header">
            <div class="tree-key">Resources</div>
            <div class="tree-item">
                %for perm_name in permissions:
                    <div class="permission-title">${perm_name}</div>
                %endfor
            </div>
        </div>
        <div class="tree">
            ${render_tree(render_resource_permissions_item, resources)}
        </div>
    </form>
</%def>


<!-- renders a single resource line in the tree with applicable permission selectors for it -->
<%def name="render_resource_permissions_item(key, value, level)">
    %for perm_name in permissions:
        ${render_resource_permissions_entry(perm_name, value)}
    %endfor
    %if not value.get("matches_remote", True):
        <div class="tree-button">
            <input type="submit" class="button-warning" value="Clean" name="clean_resource">
        </div>
        <p class="tree-item-message">
            <img title="This resource is absent from the remote server." class="icon-warning"
                 src="${request.static_url('magpie.ui.home:static/exclamation-triangle.png')}" alt="WARNING" />
        </p>
    %endif
    <div class="tree-button">
    %if level == 0:
        <form id="resource_${value['id']}_${value.get('remote_id', '')}" action="${request.path}" method="post">
            <input type="submit" class="tree-button goto-service theme" value="Edit Service" name="goto_service">
            <input type="hidden" value="${value['id']}" name="resource_id">
            <input type="hidden" value="${value.get('remote_id', '')}" name="remote_id">
            <input type="hidden" value="${value.get('matches_remote', '')}" name="matches_remote">
        </form>
    %endif
    </div>
</%def>


<!-- renders the permission selector for a single resource/permission combination -->
<%def name="render_resource_permissions_entry(permission_name, resource_info)">
    <div class="permission-entry">
        <label for="combobox_permission_resource_${resource_info['id']}">
        <select name="permission_resource_${resource_info['id']}"
                id="combobox_permission_resource_${resource_info['id']}"
            %if inherit_groups_permissions:
                disabled
                class="permission-combobox disabled"
            %else:
                class="permission-combobox"
            %endif
        >
            <option value=""></option>  <!-- none applied or remove permission -->
            %for perm_access in ["allow", "deny"]:
                %for perm_scope in ["recursive", "match"]:
                    <option value="${permission_name}-${perm_access}-${perm_scope}"
                    %if "{}-{}-{}".format(permission_name, perm_access, perm_scope) in resource_info["permission_names"]:
                        selected
                    %endif
                    >${perm_access.capitalize()}, ${perm_scope.capitalize()}</option>
                %endfor
            %endfor
        </select>
        %for perm_name in resource_info["permission_names"]:
        <input type="hidden" name="resource_${resource_info['id']}" value="${perm_name}">
        %endfor
        </label>
        <div class="permission-checkbox">
            <label>
            <!-- checkbox is only indicative of last active status retrieved for permission, therefore always disabled
                 edit via combobox options
            -->
            <input type="checkbox" value="" name="permission"
                   %if permission_name in [perm["name"] for perm in resource_info["permissions"]]:
                   checked
                   %endif
                   class="disabled"
                   disabled
            >
            </label>
        </div>
    </div>
</%def>


<%block name="sync_resources">
    <form id="sync_info" action="${request.path}" method="post">
        <p class="">  <!-- no panel-line to have normal size button -->
            %if sync_implemented:
                <input type="submit" value="Sync" name="force_sync" class="button-warning equal-width">
            %endif
            %if ids_to_clean and not out_of_sync:
                <span class="panel-entry">Note: </span>
                <span class="panel-value">Some resources are absent from the remote server </span>
                <input type="hidden" value="${ids_to_clean}" name="ids_to_clean">
                <input type="submit" class="button-warning equal-width" value="Clean all" name="clean_all">
            %endif
            <span class="panel-entry center-text sync-text">Last synchronization with remote services: </span>
            %if sync_implemented:
                <span class="panel-value center-text">${last_sync} </span>
            %else:
                <span class="panel-value center-text">Not implemented for this service type.</span>
            %endif
        </p>
    </form>
</%block>
