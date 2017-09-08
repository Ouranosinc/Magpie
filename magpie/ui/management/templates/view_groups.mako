<html>
<head>
<style>
table {
    font-family: arial, sans-serif;
    border-collapse: collapse;
    width: 100%;
}

td, th {
    border: 1px solid #dddddd;
    text-align: left;
    padding: 8px;
}

tr:nth-child(even) {
    background-color: #dddddd;
}
</style>
</head>
<body>

<h3>Groups</h3>
<form action="${request.path}" method="post">
    <input type="text" name="group_name">
    <input type="submit" value="Add Group" name="create">
</form>

<table>

%for group in group_names:
<form action="${request.path}" method="post">
<tr>
    <td><input type="hidden" value=${group} name="group_name"></td>
    <td>${group}</td>
    <td><input type="submit" value="Delete" name="delete"></td>
    <td><input type="submit" value="Edit" name="edit"></td>
</tr>
</form>
%endfor
</table>



</body>
</html>