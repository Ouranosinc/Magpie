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
            <td><input type="text" name="user_name"></td>
        </tr>
        <tr>
            <td>Email:</td>
            <td><input type="text" name="email"></td>
        </tr>
        <tr>
            <td>Password:</td>
            <td><input type="password" name="password"></td>
        </tr>
        <tr><td class="centered" colspan="2">
            <input type="radio" name="group_name" value="admin" />Admin
            <input type="radio" name="group_name" value="user" />User
            <input type="radio" name="group_name" value="guest" />Guest
        </td></tr>
        <tr><td class="centered" colspan="2"><input type="submit" value="Add User" name="create"></td></tr>
    </table>
</form>
