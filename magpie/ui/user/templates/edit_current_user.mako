<%inherit file="magpie.ui.home:templates/template.mako"/>

<%block name="breadcrumb">
    <li><a href="${request.route_url('home')}">Home</a></li>
    <li><a href="${request.route_url('edit_current_user', user_name=user_name)}">User [${user_name}]</a></li>
</%block>

%if invalid_password or invalid_user_email:
<div class="alert alert-warning alert-visible" id="UpdateUser_WarningFailureAlert">
    <h3 class="alert-title-warning">Warning</h3>
    <div class="alert-text-container alert-warning">
        <img src="${request.static_url('magpie.ui.home:static/exclamation-triangle.png')}"
             alt="" class="icon-warning icon-color-invert" />
        <div class="alert-text">
        Update User Information Failed
        </div>
    </div>
    <p>
        The user details could not be updated due to invalid format.
        Please refer to corresponding field error.
    </p>
    <form action="${request.path}" method="post">
        <input type="submit" class="button cancel" name="close" value="Close"
               onclick="this.parentElement.style.display='none';">
    </form>
</div>
%endif

<h1>Account User: [${user_name}]</h1>

<h3>User Information</h3>

<div class="alert alert-danger" id="EditService_UserSelfDeleteAlert">
    <h3 class="alert-title-danger">Danger!</h3>
    <div class="alert-danger">
        <div class="alert-text">
            <img src="${request.static_url('magpie.ui.home:static/exclamation-circle.png')}"
                 alt="" class="icon-error icon-color-invert"/>
            &nbsp;Delete your account?
        </div>
    </div>
    <p>
        This operation will delete your account and its associated permissions as well as log you out of Magpie.
        All data linked to your account will also be lost. <br> This is irreversible.
    </p>
    <p>Do you want to continue?</p>
    <form id="delete_user" action="${request.path}" method="post">
        <div>
            <input type="submit" class="button delete" name="delete" value="Delete">
            <input type="submit" class="button cancel" name="cancel" value="Cancel">
        </div>
    </form>
</div>

<div class="panel-box">
    <!-- # FIXME: implement with better warning (alert), API route supports operation
        (admin is immediate delete, but we should confirm user self-delete beforehand just in case)
    -->
    <div class="panel-heading theme">
        <span class="panel-title">User: </span>
        <span class="panel-value">[${user_name}]</span>
        <span class="panel-heading-button">
            <input value="Delete Account" name="delete"
                %if user_name in MAGPIE_FIXED_USERS:
                    class="button delete disabled" type="button" disabled
                %else:
                    type="button"
                    class="button delete"
                    onclick="document.getElementById('EditService_UserSelfDeleteAlert').style.display = 'block'"
                %endif
            >
        </span>
    </div>
    <div class="panel-body">
        <div class="panel-box">
            <div class="panel-heading subsection">
                <div class="panel-title">Details</div>
            </div>
            <!-- new table for each row to ensure long field doesn't dictate first column width -->
            <div class="panel-fields">
                <table class="panel-line">
                    <tr>
                        <td>
                            <span class="panel-entry">Username: </span>
                        </td>
                        <td>
                            <div class="panel-line-entry">
                                <!-- username fixed -->
                                <label>
                                    ${user_name}
                                </label>
                            </div>
                        </td>
                        <td></td>
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
                                                   id="input_password" value="" onkeyup="adjustWidth('input_password')">
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
                            <div class="panel-form-warning">
                                <img src="${request.static_url('magpie.ui.home:static/exclamation-triangle.png')}"
                                     alt="WARNING" class="icon-warning" />
                                <div class="alert-form-text alert-form-text-warning">
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
                                                   id="input_email" value="${email}" onkeyup="adjustWidth('input_url')">
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
                                    <img title="User account status has an issue." class="icon-warning" alt="WARNING"
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


<h3>Public Groups Membership</h3>

<form id="edit_membership" action="${request.path}" method="post">
    <input type="hidden" value="True" name="edit_group_membership"/>
    <table class="simple-list" id="current_user_groups_list">
        %for group in groups:
            <tr>
                <td>
                    <label>
                        <input type="checkbox" value="${group}" name="member"
                            %if group in joined_groups:
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
