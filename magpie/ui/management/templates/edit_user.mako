<%inherit file="magpie.ui.home:templates/template.mako"/>
<%namespace name="panel" file="magpie.ui.management:templates/panel_scripts.mako"/>
<%namespace name="tree" file="magpie.ui.management:templates/tree_scripts.mako"/>
<%namespace name="membership_alerts" file="magpie.ui.management:templates/membership_alerts.mako"/>

<%block name="breadcrumb">
<li><a href="${request.route_url('home')}">Home</a></li>
<li><a href="${request.route_url('view_users')}">Users</a></li>
<li>
    <a href="${request.route_url('edit_user', user_name=user_name, cur_svc_type=cur_svc_type)}">
    User [${user_name}]
    </a>
</li>
</%block>

<h1>Edit User: [${user_name}]</h1>

<h3>User Information</h3>


<div class="panel-box">
    <div class="panel-heading theme">
        <form id="delete_user" action="${request.path}" method="post">
            <span class="panel-title">User: </span>
            <span class="panel-value">[${user_name}]</span>
            <span class="panel-heading-button">
                <button value="Delete" name="delete"
                    %if user_name not in MAGPIE_FIXED_USERS:
                        type="submit" class="button delete"
                    %else:
                        type="button" class="button delete disabled" disabled
                    %endif
                >
                    %if user_name in MAGPIE_FIXED_USERS:
                        <img src="${request.static_url('magpie.ui.home:static/lock.png')}" alt="LOCKED"
                             class="icon-locked"/>
                        <meta name="author" content="https://www.flaticon.com/authors/those-icons">
                        <meta name="source" content="https://www.flaticon.com/free-icon/lock_2089784">
                    %else:
                        <img src="${request.static_url('magpie.ui.home:static/delete.png')}" alt=""
                             class="icon-delete">
                        <meta name="author" content="https://www.flaticon.com/authors/those-icons">
                        <meta name="source" content="https://www.flaticon.com/free-icon/delete_2089743">
                    %endif
                    Delete
                </button>
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
                            <span class="panel-entry">Username: </span>
                        </td>
                        <td>
                            %if user_name not in MAGPIE_FIXED_USERS:
                                <form id="edit_username" action="${request.path}" method="post">
                            %endif
                                <div class="panel-line-entry">
                                    %if edit_mode == "edit_username" and user_name not in MAGPIE_FIXED_USERS:
                                        <label>
                                        <input type="text" placeholder="new user name" name="new_user_name"
                                               id="input_username" value="${user_name}"
                                               onkeyup="adjustWidth('input_username')">
                                        <input type="submit" value="Save" name="save_username" class="button theme">
                                        <input type="submit" value="Cancel" name="no_edit" class="button cancel">
                                        </label>
                                    %else:
                                        <label>
                                        <span class="panel-line-textbox">${user_name}</span>
                                        %if user_name not in MAGPIE_FIXED_USERS:
                                            <input type="submit" value="Edit" name="edit_username" class="button theme">
                                        %endif
                                        </label>
                                    %endif
                                </div>
                            %if user_name not in MAGPIE_FIXED_USERS:
                                </form>
                            %endif
                        </td>
                        <td>
                        %if invalid_user_name:
                            <div class="panel-form-error">
                                <img src="${request.static_url('magpie.ui.home:static/exclamation-circle.png')}"
                                     alt="ERROR" class="icon-error" />
                                <div class="alert-form-text alert-form-text-error">
                                    ${reason_user_name}
                                </div>
                            </div>
                        %endif
                        </td>
                    </tr>
                    <tr>
                        <td>
                            <span class="panel-entry">Password: </span>
                        </td>
                        <td>
                            <form id="edit_password" action="${request.path}" method="post">
                                <div class="panel-line-entry">
                                    %if edit_mode == "edit_password" and user_name not in MAGPIE_USER_PWD_DISABLED:
                                        <label>
                                            <input type="password" placeholder="new password" name="new_user_password"
                                                   id="input_password" value=""
                                                   onkeyup="adjustWidth('input_password')">
                                            <input type="submit" value="Save" name="save_password" class="button theme">
                                            <input type="submit" value="Cancel" name="no_edit" class="button cancel">
                                        </label>
                                    %else:
                                        <label>
                                            <span class="panel-value">***</span>
                                            <input value="Edit" name="edit_password"
                                                %if user_name in MAGPIE_USER_PWD_DISABLED:
                                                   type="button" class="button theme disabled" disabled
                                                %else:
                                                   type="submit" class="button theme"
                                                %endif
                                            >
                                        </label>
                                    %endif
                                </div>
                            </form>
                        </td>
                        <td>
                        %if invalid_password:
                            <div class="panel-form-error">
                                <img src="${request.static_url('magpie.ui.home:static/exclamation-circle.png')}"
                                     alt="ERROR" class="icon-error" />
                                <div class="alert-form-text alert-form-text-error">
                                    ${reason_password}
                                </div>
                            </div>
                        %elif user_name in MAGPIE_USER_PWD_LOCKED or user_name in MAGPIE_USER_PWD_DISABLED:
                            <div class="panel-form-lock">
                                <img src="${request.static_url('magpie.ui.home:static/lock.png')}"
                                     alt="LOCKED" class="icon-locked"/>
                                <meta name="author" content="https://www.flaticon.com/authors/those-icons">
                                <meta name="source" content="https://www.flaticon.com/free-icon/lock_2089784">
                                <div class="alert-form-text alert-form-text-locked">
                                    %if user_name in MAGPIE_USER_PWD_LOCKED:
                                        This special user password is locked and can only be edited from configuration.
                                    %else:
                                        This special user password is not editable.
                                    %endif
                                </div>
                            </div>
                        %endif
                        </td>
                    </tr>
                    <tr>
                        <td>
                            <span class="panel-entry">Email: </span>
                        </td>
                        <td>
                            <form id="edit_email" action="${request.path}" method="post">
                                <div class="panel-line-entry">
                                    %if edit_mode == "edit_email":
                                        <label>
                                        <input type="email" placeholder="new email" name="new_user_email"
                                               id="input_email" value="${email}"
                                               onkeyup="adjustWidth('input_url')">
                                        <input type="submit" value="Save" name="save_email" class="button theme">
                                        <input type="submit" value="Cancel" name="no_edit" class="button cancel">
                                        </label>
                                    %else:
                                        <label>
                                        <span class="panel-value">${email}</span>
                                        <input type="submit" value="Edit" name="edit_email" class="button theme">
                                        </label>
                                    %endif
                                </div>
                            </form>
                        </td>
                        <td>
                        %if invalid_user_email:
                            <div class="panel-form-error">
                                <img src="${request.static_url('magpie.ui.home:static/exclamation-circle.png')}"
                                     alt="ERROR" class="icon-error" />
                                <div class="alert-form-text alert-form-text-error">
                                    ${reason_user_email}
                                </div>
                            </div>
                        %endif
                        </td>
                    </tr>
                    <tr>
                        <td>
                            <span class="panel-entry">Status: </span>
                        </td>
                        <td>
                            <div class="status-container">
                                %if user_with_error:
                                    <img title="User account status has an issue." class="icon-warning"
                                         alt="USER_STATUS_ERROR"
                                         src="${request.static_url('magpie.ui.home:static/exclamation-triangle.png')}"/>
                                %else:
                                    <img title="User account status is valid." class="icon-check" alt="OK"
                                         src="${request.static_url('magpie.ui.home:static/checkmark-circle.png')}"/>
                                %endif
                            </div>
                        </td>
                    </tr>
                </table>
            </div>
        </div>
    </div>
</div>


<h3>Groups Membership</h3>
${membership_alerts.edit_membership_alerts()}

<form id="edit_membership" action="${request.path}" method="post">
    <input type="hidden" value="True" name="edit_group_membership"/>
    <table class="simple-list" id="edit_user_groups_list">
    %for group in groups:
    <tr>
        <td>
            <label class="checkbox-align">
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
            %if group in pending_groups:
                <!-- checkbox is not checked or disabled for pending groups
                     so additional requests and emails can still be sent if needed -->
                ${group} [pending]
            %else:
                ${group}
            %endif
            </label>
        </td>
    </tr>
    %endfor
    </table>
</form>

<h3>Permissions</h3>

<div class="option-container">
    <div class="option-section">
        <form id="toggle_visible_perms" action="${request.path}" method="post">
            <label class="checkbox-align">
            <input type="checkbox" value="${inherit_groups_permissions}" name="toggle_inherit_groups_permissions"
                   onchange="document.getElementById('toggle_visible_perms').submit()"
            %if inherit_groups_permissions:
                checked>
                <input type="hidden" value="False" name="inherit_groups_permissions"/>
            %else:
                >
                <input type="hidden" value="True" name="inherit_groups_permissions"/>
            %endif
            <span class="option-text">
                View ${perm("inherited")} group permissions
                and ${perm("effective")} user permissions.
            </span>
            </label>
        </form>
    </div>

    %if inherit_groups_permissions:

    <div class="clear"></div>
    <div class="option-section">
        <div class="alert-note alert-visible">
            <img src="${request.static_url('magpie.ui.home:static/info.png')}"
                 alt="INFO" class="icon-info alert-info" title="User effective permission resolution." />
            <meta name="source" content="https://commons.wikimedia.org/wiki/File:Infobox_info_icon.svg">
            <div class="alert-note-text">
                <p>
                    Individual resources can be tested for ${perm("effective")} access using
                    the
                    <input type="button" value="?"
                           class="permission-effective-button permission-effective-example button-no-click"
                    >
                    <span>button next to the corresponding permission.</span>
                    <br>
                    Displayed permissions combine user ${perm("direct")} permissions
                    and ${perm("inherited")} group permissions.
                </p>
            </div>
        </div>
    </div>

    <div class="clear"></div>
    <div class="option-section">
        <div class="alert-note alert-visible">
            <img src="${request.static_url('magpie.ui.home:static/exclamation-triangle.png')}"
                 alt="WARNING" class="icon-warning" title="Administrators effective permission resolution." />
            <div class="alert-note-text">
                <p>
                    When displaying ${perm("inherited")} permissions,
                    only the highest priority item is displayed when more than one permission applies
                    for the corresponding resource.
                    <br>
                    Priority of ${perm("inherited")} permission is as follows (highest first):
                </p>
                <ol>
                    <li>User [deny]</li>
                    <li>User [allow]</li>
                    <li>Group (generic) [deny]</li>
                    <li>Group (generic) [allow]</li>
                    <li>Group (${MAGPIE_ANONYMOUS_GROUP}}) [deny]</li>
                    <li>Group (${MAGPIE_ANONYMOUS_GROUP}) [allow]</li>
                </ol>
            </div>
        </div>
    </div>

    <div class="clear"></div>
    <div class="option-section">
        <div class="alert-note alert-visible">
            <img src="${request.static_url('magpie.ui.home:static/exclamation-triangle.png')}"
                 alt="WARNING" class="icon-warning" title="Administrators effective permission resolution." />
            <div class="alert-note-text">
                <p>
                    Users member of the administrative group have
                    full ${perm("effective")}
                    access regardless of permissions.
                </p>
            </div>
        </div>
    </div>
    %endif
</div>

<div class="clear"></div>
<div class="tabs-panel">
    ${panel.render_tab_selector(cur_svc_type, [
        (svc_type, request.route_url("edit_user", user_name=user_name, cur_svc_type=svc_type))
        for svc_type in svc_types
    ])}

    <div class="current-tab-panel">
        <div class="clear"></div>
        %if error_message:
            <div class="alert alert-danger alert-visible">${error_message}</div>
        %endif

        ${tree.sync_resources()}
        ${tree.render_resource_permission_tree(resources, permissions)}
    </div>
</div>

<!-- perm_type must be one of [direct, inherited, effective] -->
<%def name="perm(perm_type)">
<span class="perm-info-text">
    <a href="https://pavics-magpie.readthedocs.io/en/latest/glossary.html#term-${perm_type.capitalize()}-Permissions"
    >${perm_type.lower()}</a>  <!-- spacing important -->
</span>
</%def>
