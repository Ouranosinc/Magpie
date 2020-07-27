<%inherit file="ui.home:templates/template.mako"/>

<%block name="breadcrumb">
<li><a href="${request.route_url('home')}">Home</a></li>
<li><a href="${request.route_url('edit_current_user', user_name=user_name)}">User [${user_name}]</a></li>
</%block>

<h1>Account User: ${user_name}</h1>

<h3>User Information</h3>


<div class="panel_box">
    <!-- # FIXME: should we have a route that allows user to unregister itself?
    <form id="delete_user" action="${request.path}" method="post">
        <div class="panel_heading">
            <span class="panel_title">User: </span>
            <span class="panel_value">${user_name}</span>
            <span class="panel_heading_button">
                <input type="submit" value="Delete" name="delete" class="button delete">
            </span>
        </div>
    </form>
    -->
    <div class="panel_body">
        <div class="panel_box">
            <div class="panel_heading">
                <div class="panel_title">Details</div>
            </div>
            <div>
                <!-- username fixed -->
                <p class="panel_line">
                    <span class="panel_entry">Username: </span>
                    ${user_name}
                </p>
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


<h3>Public Groups Membership</h3>

<form id="edit_membership" action="${request.path}" method="post">
    <input type="hidden" value="True" name="edit_group_membership"/>
    <table>
    %for group in groups:
    <tr>
        <td>
            <label>
            <input type="checkbox" value="${group}" name="member"
               % if group in joined_groups:
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
