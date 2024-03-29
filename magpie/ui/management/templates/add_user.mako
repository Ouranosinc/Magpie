<%inherit file="magpie.ui.home:templates/template.mako"/>

<%block name="breadcrumb">
<li><a href="${request.route_url('home')}">Home</a></li>
%if is_registration:
    <li><a href="${request.route_url('add_user')}">Register</a></li>
%else:
    <li><a href="${request.route_url('view_users')}">Users</a></li>
    <li><a href="${request.route_url('add_user')}">Add User</a></li>
%endif
</%block>

<h1>
    %if is_registration:
    Register
    %else:
    Add User
    %endif
</h1>

<form class="new-item-form" id="add_user_form" action="${request.path}" method="post">
    <table class="fields-table">
        <tr>
            <td>User name:</td>
            <td><div class="input-container"><label>
                <input type="text" name="user_name" placeholder="username"
                       value="${form_user_name}" class="equal-width">
                </label></div>
            </td>
            <td>
                <div class="alert-form-error"
                    %if not invalid_user_name:
                        style="visibility: hidden"
                    %endif
                >
                    <img src="${request.static_url('magpie.ui.home:static/exclamation-circle.png')}"
                         alt="ERROR" class="icon-error" />
                    <div class="alert-form-text alert-form-text-error">
                        %if invalid_user_name:
                            ${reason_user_name}
                        %endif
                    </div>
                </div>
            </td>
        </tr>
        <tr>
            <td>Email:</td>
            <td><div class="input-container"><label>
                <input type="email" name="email" placeholder="email"
                       value="${form_user_email}" class="equal-width">
                </label></div>
            </td>
            <td>
                <div class="alert-form-error"
                    %if not invalid_user_email:
                        style="visibility: hidden"
                    %endif
                >
                    <img src="${request.static_url('magpie.ui.home:static/exclamation-circle.png')}"
                         alt="ERROR" class="icon-error" />
                    <div class="alert-form-text alert-form-text-error">
                        %if invalid_user_email:
                            ${reason_user_email}
                        %endif
                    </div>
                </div>
            </td>
        </tr>
        <tr>
            <td>Password:</td>
            <td>
                <div class="input-container"><label>
                <input type="password" placeholder="password"
                       name="password" value="" class="equal-width">
                </label></div>
            </td>
            <td>
                <div class="alert-form-error"
                    %if not invalid_password:
                        style="visibility: hidden"
                    %endif
                >
                    <img src="${request.static_url('magpie.ui.home:static/exclamation-circle.png')}"
                         alt="ERROR" class="icon-error" />
                    <div class="alert-form-text alert-form-text-error">
                        %if invalid_password:
                            ${reason_password}
                        %endif
                    </div>
                </div>
            </td>
        </tr>
        <tr>
            <td>Confirm:</td>
            <td>
                <div class="input-container"><label>
                <input type="password" placeholder="confirm"
                       name="confirm" value="" class="equal-width">
                </label></div>
            </td>
            <td>
                <div class="alert-form-error"
                    %if not invalid_password:
                        style="visibility: hidden"
                    %endif
                >
                    <img src="${request.static_url('magpie.ui.home:static/exclamation-circle.png')}"
                         alt="ERROR" class="icon-error" />
                    <div class="alert-form-text alert-form-text-error">
                        ${reason_password}
                    </div>
                </div>
            </td>
        </tr>
        %if not is_registration:
        <tr>
            <td>User group:</td>
            <td class="centered" colspan="2">
                <div class="input-container">
                <label>
                <select name="group_name" class="equal-width">
                    %for group in user_groups:
                        <option value="${group}">${group}</option>
                    %endfor
                </select>
                </label>
                </div>
            </td>
        </tr>
        %endif
        <tr>
            <td class="centered" colspan="2">
                <input type="submit" name="create" class="button theme"
                %if is_registration:
                    value="Register"
                %else:
                    value="Add User"
                %endif
                >
            </td>
        </tr>
    </table>
</form>
