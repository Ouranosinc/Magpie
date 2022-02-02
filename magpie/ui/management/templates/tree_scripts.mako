<%inherit file="magpie.ui.home:templates/template.mako"/>


<!-- renders a tree of nested service/resources using the provided item renderer function
     see 'tree_scripts.js' for toggling even
-->
<%def name="render_tree(item_renderer, tree, level=0)">
    <ul class="tree-level-${level}">
    %for key in tree:
        %if tree[key]["children"]:
        <li class="collapsible expanded" id="${tree[key]['id']}">
        <div class="collapsible-marker"></div>
        %else:
        <li class="no-child" id="${tree[key]['id']}">
        %endif
            <div class="tree-line">
                ${item_renderer(key, tree[key], level)}
            </div>
            <div class="clear underline"></div>
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
        <div class="permission-apply-container">
            <input type="submit" name="edit_permissions" value="Apply Permissions" title="Apply the permission changes"
                %if inherit_groups_permissions:
                    disabled
                    class="button theme disabled"
                %else:
                    class="button theme"
                %endif
            >
        </div>

        <div class="tree-header">
            <div class="tree-line-key-container tree-key">Resources</div>
            <div class="tree-line-fill-container"><!-- --></div>
            <div class="tree-line-item-container tree-item">
                <div class="tree-line-item-container-scrollable tree-line-scroll-visible">
                    %for perm_name in permission_titles:
                        <div
                        %if inherit_groups_permissions:
                            class="permission-cell permission-title permission-title-effective"
                        %else:
                            class="permission-cell permission-title"
                        %endif
                        >${perm_name}</div>
                    %endfor
                </div>
            </div>
        </div>
        <div class="tree">
            ${render_tree(render_resource_permissions_item, resources)}
        </div>
    </form>
</%def>


<!-- renders a single resource line in the tree with applicable permission selectors for it -->
<%def name="render_resource_permissions_item(key, value, level)">
    <div class="tree-line-key-container tree-item-value collapsible-tree-item">
        <span class="tree-item-label label label-info">${value["resource_type"]}</span>
        <div class="tree-key tooltip-container">
            <span class="tooltip-value tree-key-value">${value.get('resource_display_name', key)}</span>
            <span class="tooltip-text">Resource: ${value["id"]}</span>
        </div>
    </div>
    <div class="tree-line-fill-container">
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
    </div>
    <div class="tree-line-item-container">
        <div class="tree-line-item-container-scrollable">
            %for perm_name in permissions:
                ${render_resource_permissions_entry(perm_name, value)}
            %endfor
        </div>
    </div>
</%def>


<!-- renders the permission selector for a single resource/permission combination -->
<%def name="render_resource_permissions_entry(permission_name, resource_info)">
    <div class="permission-cell permission-entry">
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

        <!-- previous state of existing permissions to detect removal of permission vs already blank selectors -->
        %for perm_name in resource_info["permission_names"]:
            <input type="hidden" name="resource_${resource_info['id']}" value="${perm_name}">
        %endfor
        </label>

        ${effective_button_test(user_name, resource_info['id'], permission_name)}

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


<!-- creates a test button for effective permission for corresponding user/resource/permission by calling the API
     once resolved, the response is parsed and displays either a checkmark or cross in place of the test button
 -->
<%def name="effective_button_test(user_name, resource_id, permission_name)">
%if inherit_groups_permissions:
    <script type="text/javascript">
        function testPermissionEffective(host, userName, resourceId, permName) {
            $.ajax({
                url: host + "/users/" + userName + "/resources/" + resourceId + "/permissions?effective=true",
                type: "get",
                dataType: "json",
                contentType: "application/json",
                success: function (data) {
                    let permissions = data["permissions"];
                    let result = $("#PermissionEffectiveFailure_" + resourceId + "_" + permName);
                    $.each(permissions, function(_, perm){
                        if (perm.name === permName && perm.access === "allow") {
                            console.log("perm found! ", permName, perm.name, perm.access);
                            result = $("#PermissionEffectiveSuccess_" + resourceId + "_" + permName);
                            return false;
                        }
                    });
                    let btn = $("#PermissionEffectiveButton_" + resourceId + "_" + permName);
                    btn.hide();
                    result.toggleClass("hidden");
                },
            });
        }
    </script>
    <div class="permission-effective-tester" id="PermissionEffective_${resource_id}_${permission_name}">
        <input type="button" value="?" id="PermissionEffectiveButton_${resource_id}_${permission_name}"
               class="permission-effective-button"
               onclick="testPermissionEffective('${MAGPIE_URL}', '${user_name}', '${resource_id}', '${permission_name}');">
        <div class="permission-effective success hidden"
             id="PermissionEffectiveSuccess_${resource_id}_${permission_name}">☑</div>
        <div class="permission-effective failure hidden"
             id="PermissionEffectiveFailure_${resource_id}_${permission_name}">☒</div>
    </div>
%endif
</%def>


<%block name="sync_resources">
    <div>
        <form id="sync_info" action="${request.path}" method="post"
            %if sync_implemented:
              onsubmit="document.getElementById('sync-loading').style.display='revert';"
            %endif
        >
            <div class="no-border">  <!-- no panel-line to have normal size button -->
                %if sync_implemented:
                    <input type="submit" value="Sync" name="force_sync" class="button-warning equal-width">
                    <img class="icon-loading" style="display: none" id="sync-loading"
                         src="${request.static_url('magpie.ui.home:static/loading.gif')}" alt="SYNCING..."/>
                %endif
                <div class="align-text">
                %if ids_to_clean and not out_of_sync:
                    <span class="panel-entry">Note: </span>
                    <span class="panel-value">Some resources are absent from the remote server </span>
                    <input type="hidden" value="${ids_to_clean}" name="ids_to_clean">
                    <input type="submit" class="button-warning equal-width" value="Clean all" name="clean_all">
                %endif
                <span class="panel-entry sync-text">Last synchronization with remote services: </span>
                %if sync_implemented:
                    <span class="panel-value">${last_sync} </span>
                %else:
                    <span class="panel-value">Not implemented for this service type.</span>
                %endif
                </div>
            </div>
        </form>
    </div>
</%block>
