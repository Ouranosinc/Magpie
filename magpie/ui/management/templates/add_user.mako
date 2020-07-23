<%inherit file="ui.home:templates/template.mako"/>

<%block name="breadcrumb">
<li><a href="${request.route_url('home')}">Home</a></li>
<li><a href="${request.route_url('view_users')}">Users</a></li>
<li><a href="${request.route_url('add_user')}">Add User</a></li>
</%block>

<h1>Add User</h1>

<form class="new_item_form" id="add_user_form" action="${request.path}" method="post">
    <table class="fields_table">
        <tr>
            <td>User name:</td>
            <td><div class="input_container"><label>
                <input type="text" name="user_name" value="${form_user_name}" class="equal_width">
                </label></div>
            </td>
            %if too_long_user_name:
                <td><p class="alert_form_error">
                    <img src="${request.static_url('magpie.ui.home:static/warning_exclamation.png')}" alt="WARNING" />
                    Too long </p>
                </td>
            %elif invalid_user_name:
                <td><p class="alert_form_error">
                    <img src="${request.static_url('magpie.ui.home:static/warning_exclamation.png')}" alt="WARNING" />
                    Invalid </p>
                </td>
            %elif conflict_user_name:
                <td><p class="alert_form_error">
                    <img src="${request.static_url('magpie.ui.home:static/warning_exclamation.png')}" alt="WARNING" />
                    Conflict </p>
                </td>
            %else:
                <td><p class="alert_form_error">&nbsp;</p></td> <!-- empty cell to keep table shape consistent -->
            %endif
        </tr>
        <tr>
            <td>Email:</td>
            <td><div class="input_container"><label>
                <input type="text" name="email" value="${form_user_email}" class="equal_width">
                </label></div>
            </td>
            %if invalid_user_email:
                <td><p class="alert_form_error">
                    <img src="${request.static_url('magpie.ui.home:static/warning_exclamation.png')}" alt="WARNING" />
                    Invalid </p>
                </td>
            %elif conflict_user_email:
                <td><p class="alert_form_error">
                    <img src="${request.static_url('magpie.ui.home:static/warning_exclamation.png')}" alt="WARNING" />
                    Conflict </p>
                </td>
            %else:
                <td><p class="alert_form_error">&nbsp;</p></td> <!-- empty cell to keep table shape consistent -->
            %endif
        </tr>
        <tr>
            <td>Password:</td>
            <td>
                <div class="input_container"><label>
                <input type="password" name="password" value="" class="equal_width">
                </label></div>
            </td>
            %if invalid_password:
                <td><p class="alert_form_error">
                    <img src="${request.static_url('magpie.ui.home:static/warning_exclamation.png')}" alt="WARNING" />
                    Invalid </p>
                </td>
            %else:
                <td><p class="alert_form_error">&nbsp;</p></td> <!-- empty cell to keep table shape consistent -->
            %endif
        </tr>
        <tr>
            <td>User group:</td>
            <td class="centered" colspan="2">
                <div class="input_container">
                <label>
                <select name="group_name" class="equal_width">
                    %for group in user_groups:
                        <option value="${group}">${group}</option>
                    %endfor
                </select>
                </label>
                </div>
            </td>
        </tr>
        <tr><td class="centered" colspan="2"><input type="submit" value="Add User" name="create"></td></tr>
    </table>
</form>
