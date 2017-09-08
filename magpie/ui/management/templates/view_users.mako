<html>
<head>
<link href="${request.static_url('management:static/style.css')}" rel="stylesheet" type="text/css" media="all" />
</head>
<body>

<h3>Users</h3>
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

<table>

%for user in users:
<form action="${request.path}" method="post">
<tr>
    <td><input type="hidden" value=${user} name="user_name"></td>
    <td>${user}</td>
    <td><input type="submit" value="Delete" name="delete"></td>
    <td><input type="submit" value="Edit" name="edit"></td>
</tr>
</form>
%endfor
</table>



</body>
</html>