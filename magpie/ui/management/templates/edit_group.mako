<%inherit file="magpie.ui.management:templates/tree_scripts.mako"/>
<%namespace name="panel" file="magpie.ui.management:templates/panel_scripts.mako"/>
<%namespace name="tree" file="magpie.ui.management:templates/tree_scripts.mako"/>
<%namespace name="membership_alerts" file="magpie.ui.management:templates/membership_alerts.mako"/>

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
                <button value="Delete" name="delete"
                    %if group_name in MAGPIE_FIXED_GROUP_EDITS:
                        class="button delete disabled" type="button" disabled
                    %else:
                        class="button delete" type="submit"
                    %endif
                >
                    %if group_name in MAGPIE_FIXED_GROUP_EDITS:
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
                        <td class="panel-entry-title">
                            <div class="panel-entry">Name: </div>
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
                        <td>
                            %if group_name in MAGPIE_FIXED_GROUP_EDITS:
                                <div class="panel-form-lock">
                                    <img src="${request.static_url('magpie.ui.home:static/lock.png')}"
                                         alt="LOCKED" class="icon-locked"/>
                                    <meta name="author"
                                          content="https://www.flaticon.com/authors/those-icons">
                                    <meta name="source"
                                          content="https://www.flaticon.com/free-icon/lock_2089784">
                                    <div class="alert-form-text alert-form-text-locked">
                                        Edit not allowed for this special group.
                                    </div>
                                </div>
                            %endif
                        </td>
                    </tr>
                    <tr>
                        <td class="panel-entry-title">
                            <div class="panel-entry">Description: </div>
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
                        <td>
                        </td>
                    </tr>
                    <tr>
                        <td class="panel-entry-title">
                            <div class="panel-entry">Discoverable: </div>
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
                        <td>
                        </td>
                    </tr>
                </table>
            </div>
        </div>
        <div class="panel-box">
            <div class="panel-heading subsection">
                <div class="panel-title">Terms and conditions</div>
            </div>
            <div class="panel-body">
                %if terms:
                    ${terms}
                %else:
                    <span class="italic-text">No terms and conditions for this group.</span>
                %endif
            </div>
        </div>
    </div>
</div>

<h3>Members</h3>
${membership_alerts.edit_membership_alerts()}

<form id="edit_members" action="${request.path}" method="post">
    <input type="hidden" value="True" name="edit_group_members"/>
    <table class="simple-list" id="edit_group_members_list">
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
            %if user in pending_users:
                <!-- checkbox is not checked or disabled for pending users
                     so additional requests and emails can still be sent if needed -->
                ${user} [pending]
            %else:
                ${user}
            %endif
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
        <div class="clear"></div>
        %if error_message:
            <div class="alert alert-danger alert-visible">${error_message}</div>
        %endif

        ${tree.sync_resources()}
        ${tree.render_resource_permission_tree(resources, permissions)}
    </div>
</div>
