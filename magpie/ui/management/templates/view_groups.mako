<%inherit file="home:templates/template.mako"/>

<%block name="breadcrumb">
<li><a href="${request.route_url('home')}">Home</a></li>
<li><a href="${request.route_url('view_groups')}">Groups</a></li>
</%block>

<h1>Groups</h1>


<button class="img_button" type="button" onclick="location.href='${request.route_url('add_group')}'">
    <img src="${request.static_url('home:static/add.png')}">
    Add Group
</button>

<table class="simple_list_table">

%for group in group_names:
<form action="${request.path}" method="post">
<tr>
    <td><input type="hidden" value=${group} name="group_name">${group}</td>
    <td><input type="submit" value="Delete" name="delete"></td>
    <td><input type="submit" value="Edit" name="edit"></td>
</tr>
</form>
%endfor
</table>