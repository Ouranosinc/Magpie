<%inherit file="magpie.ui.management:templates/tree_scripts.mako"/>
<%namespace name="panel" file="magpie.ui.management:templates/panel_scripts.mako"/>
<%namespace name="tree" file="magpie.ui.management:templates/tree_scripts.mako"/>

<%block name="breadcrumb">
<li><a href="${request.route_url('home')}">Home</a></li>
<li><a href="${request.route_url('view_groups')}">Groups</a></li>
<li>
    <a href="${request.route_url('edit_group', group_name=group_name, cur_svc_type=cur_svc_type)}">
    Group [${group_name}]
    </a>
</li>
</%block>

<h1>Edit Group: [${group_name}]</h1>


<h3>Group Information</h3>

<div class="panel-box">
    <div class="panel-heading theme">
        <form id="delete_group" action="${request.path}" method="post">
            <span class="panel-title">Group: </span>
            <span class="panel-value">[${group_name}]</span>
            <span class="panel-heading-button">
                <input value="Delete" name="delete"
                    %if group_name in MAGPIE_FIXED_GROUP_EDITS:
                        class="button delete disabled" type="button" disabled
                    %else:
                        class="button delete" type="submit"
                    %endif
                >
            </span>
        </form>
    </div>
    <div class="panel-body">
        <div class="panel-box">
            <div class="panel-heading subsection">
                <div class="panel-title">Details</div>
            </div>
            <div class="panel-fields">
                <table class="panel-line">
                    <tr>
                        <td>
                            <span class="panel-entry">Name: </span>
                        </td>
                        <td>
                            <form id="edit_name" action="${request.path}" method="post">
                                <div class="panel-line-entry">
                                    %if edit_mode == "edit_group_name" and group_name not in MAGPIE_FIXED_GROUP_EDITS:
                                        <label>
                                        <input type="text" placeholder="group name" name="new_group_name"
                                               id="input_group_name" value="${group_name}"
                                               onkeyup="adjustWidth('input_group_name')">
                                        <input type="submit" value="Save" name="save_group_name" class="button theme">
                                        <input type="submit" value="Cancel" name="no_edit" class="button cancel">
                                        </label>
                                    %else:
                                        <label>
                                        <span class="panel-line-textbox">${group_name}</span>
                                        %if group_name not in MAGPIE_FIXED_GROUP_EDITS:
                                        <input type="submit" value="Edit" name="edit_group_name" class="button theme">
                                        %endif
                                        </label>
                                    %endif
                                </div>
                            </form>
                        </td>
                    </tr>
                    <tr>
                        <td>
                            <span class="panel-entry">Description: </span>
                        </td>
                        <td>
                            <form id="edit_description" action="${request.path}" method="post">
                                <div class="panel-line-entry">
                                    %if edit_mode == "edit_description" and group_name not in MAGPIE_FIXED_GROUP_EDITS:
                                        <label>
                                        <input type="text" placeholder="description" name="new_description"
                                               id="input_description" onkeyup="adjustWidth('input_description')"
                                            %if description:
                                                value="${description}"
                                            %endif
                                        >
                                        <input type="submit" value="Save" name="save_description" class="button theme">
                                        <input type="submit" value="Cancel" name="no_edit" class="button cancel">
                                        </label>
                                    %else:
                                        <label>
                                        <span class="panel-line-textbox">
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
                                </div>
                            </form>
                        </td>
                    </tr>
                    <tr>
                        <td>
                            <span class="panel-entry">Discoverable: </span>
                        </td>
                        <td>
                            <form id="edit_discoverable" action="${request.path}" method="post">
                                <div class="panel-line-entry">
                                    <label class="checkbox-align panel-line-checkbox">
                                    <!-- when unchecked but checkbox pressed checkbox 'value' not actually sent -->
                                    <input type="hidden" value="${discoverable}" name="is_discoverable"/>
                                    <input type="checkbox" name="new_discoverable"
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
                                </div>
                            </form>
                        </td>
                    </tr>
                </table>
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
        <label class="checkbox-align">
        <input type="checkbox" value="${user}" name="member"
            %if user in members:
               checked
            %endif
            %if group_name in MAGPIE_FIXED_GROUP_MEMBERSHIPS:
               disabled
               class="disabled"
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
    ${panel.render_tab_selector(cur_svc_type, [
        (svc_type, request.route_url("edit_group", group_name=group_name, cur_svc_type=svc_type))
        for svc_type in svc_types
    ])}

    <div class="current-tab-panel">
        <div class="clear underline"></div>
        %if error_message:
            <div class="alert alert-danger alert-visible">${error_message}</div>
        %endif

        ${tree.sync_resources()}
        ${tree.render_resource_permission_tree(resources, permissions)}
    </div>
</div>
