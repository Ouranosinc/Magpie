<%inherit file="home:templates/template.mako"/>

<%block name="breadcrumb">
<li><a href="${request.route_url('home')}">Home</a></li>
<li><a href="${request.route_url('view_users')}">Users</a></li>
<li><a href="${request.route_url('add_user')}">Add User</a></li>
</%block>

<h1>Add User</h1>

<form action="${request.path}" method="post">
    <table>
        <tr>
            <td>User name</td>
            <td><input type="text" name="user_name"></td>
        </tr>
        <tr>
            <td>Email</td>
            <td><input type="text" name="email"></td>
        </tr>
        <tr>
            <td>Password</td>
            <td><input type="password" name="password"></td>
        </tr>
    </table>
    <input type="radio" name="group_name" value="admin" />Admin<br>
    <input type="radio" name="group_name" value="user" />User<br>
    <input type="radio" name="group_name" value="guest" />Guest<br>
    <input type="submit" value="Add User" name="create">
</form>
