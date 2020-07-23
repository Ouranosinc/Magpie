<%inherit file="ui.home:templates/template.mako"/>

<%block name="breadcrumb">
<li><a href="${request.route_url('home')}">Home</a></li>
<li><a href="${request.route_url('view_groups')}">Groups</a></li>
</%block>

<h1>Groups</h1>


<button class="img_button" type="button" onclick="location.href='${request.route_url('add_group')}'">
    <img src="${request.static_url('magpie.ui.home:static/add.png')}" alt="">
    Add Group
</button>

<table class="simple_list_table">
<tr>
    <th>Group</th>
    <th>Members count</th>
    <th>Action</th>
</tr>
%for group in group_names:
<form action="${request.path}" method="post">
<tr>
    <td><input type="hidden" value=${group} name="group_name">${group}</td>
    <td>${group_names[group]['members']}</td>
    <td style="white-space: nowrap">
        <input type="submit" value="Edit" name="edit">
        <input type="submit" value="Delete" name="delete" class="button delete">
    </td>
</tr>
</form>
%endfor
</table>
