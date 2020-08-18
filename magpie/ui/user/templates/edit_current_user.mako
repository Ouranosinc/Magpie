<%inherit file="ui.home:templates/template.mako"/>

<%block name="breadcrumb">
<li><a href="${request.route_url('home')}">Home</a></li>
<li><a href="${request.route_url('edit_current_user', user_name=user_name)}">User [${user_name}]</a></li>
</%block>

<h1>Account User: [${user_name}]</h1>

<h3>User Information</h3>


<div class="panel-box">
    <!-- # FIXME: implement with better warning (alert), API route supports operation
        (admin is immediate delete, but we should confirm user self-delete beforehand just in case)
    -->
    <div class="panel-heading theme">
    <!--
    <form id="delete_user" action="${request.path}" method="post">
    -->
        <span class="panel-title">User: </span>
        <span class="panel-value">[${user_name}]</span>
    <!--
        <span class="panel-heading-button">
            <input type="submit" value="Delete Account" name="delete" class="button delete">
        </span>
    </form>
    -->
    </div>
    <div class="panel-body">
        <div class="panel-box">
            <div class="panel-heading subsection">
                <div class="panel-title">Details</div>
            </div>
            <div>
                <!-- username fixed -->
                <p class="panel-line">
                    <span class="panel-entry">Username: </span>
                    ${user_name}
                </p>
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


<h3>Public Groups Membership</h3>

<form id="edit_membership" action="${request.path}" method="post">
    <input type="hidden" value="True" name="edit_group_membership"/>
    <table class="simple-list">
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
