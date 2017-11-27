<%inherit file="ui.home:templates/template.mako"/>

<%block name="breadcrumb">
<li><a href="${request.route_url('home')}">Home</a></li>
<li><a href="${request.route_url('view_users')}">Users</a></li>
<li><a href="${request.route_url('add_user')}">Add User</a></li>
</%block>

<h1>Add User</h1>

<form class="new_item_form" action="${request.path}" method="post">
    <table class="fields_table">
        <tr>
            <td>User name:</td>
            <div class="input_container">
                <td><input type="text" name="user_name" class="equal_width"></td>
            </div>
            %if invalid_user_name:
                <td><p class="alert_conflict">
                    <img src="${request.static_url('ui.home:static/warning_exclamation.png')}" /> Invalid </p>
                </td>
            %endif
            %if conflict_user_name:
                <td><p class="alert_conflict">
                    <img src="${request.static_url('ui.home:static/warning_exclamation.png')}" /> Conflict </p>
                </td>
            %endif
        </tr>
        <tr>
            <td>Email:</td>
            <div class="input_container">
                <td><input type="text" name="email" class="equal_width"></td>
            </div>
            %if invalid_email:
                <td><p class="alert_conflict">
                    <img src="${request.static_url('ui.home:static/warning_exclamation.png')}" /> Invalid </p>
                </td>
            %endif
            %if conflict_email:
                <td><p class="alert_conflict">
                    <img src="${request.static_url('ui.home:static/warning_exclamation.png')}" /> Conflict </p>
                </td>
            %endif
        </tr>
        <tr>
            <td>Password:</td>
            <div class="input_container">
                <td><input type="password" name="password" class="equal_width"></td>
            </div>
            %if invalid_password:
                <td><p class="alert_conflict">
                    <img src="${request.static_url('ui.home:static/warning_exclamation.png')}" /> Invalid </p>
                </td>
            %endif
        </tr>
        <tr>
            <td>User group:</td>
            <div class="input_container">
                <td class="centered" colspan="2">
                <select name="group_name" class="equal_width">
                    %for group in user_groups:
                        <option value="${group}">${group}</option>
                    %endfor
                </select></td>
            </div>
        </tr>
        <tr><td class="centered" colspan="2"><input type="submit" value="Add User" name="create"></td></tr>
    </table>
</form>
