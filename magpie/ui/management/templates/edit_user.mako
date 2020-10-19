<%inherit file="magpie.ui.home:templates/template.mako"/>
<%inherit file="magpie.ui.management:templates/tree_scripts.mako"/>
<%namespace name="tree" file="magpie.ui.management:templates/tree_scripts.mako"/>

<%block name="breadcrumb">
<li><a href="${request.route_url('home')}">
    Home</a></li>
<li><a href="${request.route_url('view_users')}">
    Users</a></li>
<li><a href="${request.route_url('edit_user', user_name=user_name, cur_svc_type=cur_svc_type)}">
    User [${user_name}]</a></li>
</%block>

<h1>Edit User: [${user_name}]</h1>

<h3>User Information</h3>


<div class="panel-box">
    <div class="panel-heading theme">
        <form id="delete_user" action="${request.path}" method="post">
            <span class="panel-title">User: </span>
            <span class="panel-value">[${user_name}]</span>
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
            <div class="panel-fields">
                <form id="edit_username" action="${request.path}" method="post">
                    <p class="panel-line">
                        <span class="panel-entry">Username: </span>
                        %if edit_mode == 'edit_username':
                            <label>
                            <input type="text" placeholder="new user name" value="${user_name}" name="new_user_name"
                                   id="input_username" onkeyup="adjustWidth('input_username')">
                            <input type="submit" value="Save" name="save_username" class="button theme">
                            <input type="submit" value="Cancel" name="no_edit" class="button cancel">
                            </label>
                        %else:
                            <label>
                            <span class="panel-value">${user_name}</span>
                            <input type="submit" value="Edit" name="edit_username" class="button theme">
                            </label>
                        %endif
                    </p>
                </form>
                <form id="edit_password" action="${request.path}" method="post">
                    <p class="panel-line">
                        <span class="panel-entry">Password: </span>
                        %if edit_mode == "edit_password":
                            <label>
                            <input type="password" placeholder="new password" value="" name="new_user_password"
                                   id="input_password" onkeyup="adjustWidth('input_password')">
                            <input type="submit" value="Save" name="save_password" class="button theme">
                            <input type="submit" value="Cancel" name="no_edit" class="button cancel">
                            </label>
                        %else:
                            <label>
                            <span class="panel-value">***</span>
                            <input type="submit" value="Edit" name="edit_password" class="button theme">
                            </label>
                        %endif
                    </p>
                </form>
                <form id="edit_email" action="${request.path}" method="post">
                    <p class="panel-line">
                        <span class="panel-entry">Email: </span>
                        %if edit_mode == "edit_email":
                            <label>
                            <input type="email" placeholder="new email" value="${email}" name="new_user_email"
                                   id="input_email" onkeyup="adjustWidth('input_url')">
                            <input type="submit" value="Save" name="save_email" class="button theme">
                            <input type="submit" value="Cancel" name="no_edit" class="button cancel">
                            </label>
                        %else:
                            <label>
                            <span class="panel-value">${email}</span>
                            <input type="submit" value="Edit" name="edit_email" class="button theme">
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
    <table class="simple-list">
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
    <div class="panel-line">
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
        <span class="center-text">
        View inherited group permissions
        </span>
        </label>
    </div>
</form>

<div class="tabs-panel">

    <%block cached="True" cache_timeout="3600">
    %for svc_type in svc_types:
        % if cur_svc_type == svc_type:
            <a class="tab current-tab"
               href="${request.route_url('edit_user', user_name=user_name, cur_svc_type=svc_type)}">${svc_type}</a>
        % else:
            <a class="tab theme"
               href="${request.route_url('edit_user', user_name=user_name, cur_svc_type=svc_type)}">${svc_type}</a>
        % endif
    %endfor
    </%block>

    <div class="current-tab-panel">
        <div class="clear"></div>
        %if error_message:
            <div class="alert alert-danger alert-visible">${error_message}</div>
        %endif

        ${tree.sync_resources()}
        ${tree.render_resource_permission_tree(resources, permissions)}
    </div>
</div>
