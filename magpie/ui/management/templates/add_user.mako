<%inherit file="ui.home:templates/template.mako"/>

<%block name="breadcrumb">
<li><a href="${request.route_url('home')}">Home</a></li>
<li><a href="${request.route_url('view_users')}">Users</a></li>
<li><a href="${request.route_url('add_user')}">Add User</a></li>
</%block>

<h1>Add User</h1>

<form class="new-item-form" id="add_user_form" action="${request.path}" method="post">
    <table class="fields-table">
        <tr>
            <td>User name:</td>
            <td><div class="input-container"><label>
                <input type="text" name="user_name" value="${form_user_name}" class="equal-width">
                </label></div>
            </td>
            <td>
                <div class="alert-form-error">
                    <img src="${request.static_url('magpie.ui.home:static/exclamation-circle.png')}"
                         alt="ERROR" class="icon-error" />
                    <div class="alert-form-text">
                        %if too_long_user_name:
                            Too Long
                        %elif invalid_user_name:
                            Invalid
                        %elif conflict_user_name:
                            Conflict
                        %endif
                    </div>
                </div>
            </td>
        </tr>
        <tr>
            <td>Email:</td>
            <td><div class="input-container"><label>
                <input type="text" name="email" value="${form_user_email}" class="equal-width">
                </label></div>
            </td>
            <td>
                <div class="alert-form-error">
                    <img src="${request.static_url('magpie.ui.home:static/exclamation-circle.png')}"
                         alt="ERROR" class="icon-error" />
                    <div class="alert-form-text">
                        %if invalid_user_email:
                            Invalid
                        %elif conflict_user_email:
                            Conflict
                        %endif
                    </div>
                </div>
            </td>
        </tr>
        <tr>
            <td>Password:</td>
            <td>
                <div class="input-container"><label>
                <input type="password" name="password" value="" class="equal-width">
                </label></div>
            </td>
            <td>
                <div class="alert-form-error">
                    <img src="${request.static_url('magpie.ui.home:static/exclamation-circle.png')}"
                         alt="ERROR" class="icon-error" />
                    <div class="alert-form-text">
                        %if invalid_password:
                            Invalid
                        %endif
                    </div>
                </div>
            </td>
        </tr>
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
        <tr>
            <td class="centered" colspan="2">
                <input type="submit" value="Add User" name="create" class="button theme">
            </td>
        </tr>
    </table>
</form>
