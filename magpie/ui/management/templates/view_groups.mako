<%inherit file="magpie.ui.home:templates/template.mako"/>

<%block name="breadcrumb">
<li><a href="${request.route_url('home')}">Home</a></li>
<li><a href="${request.route_url('view_groups')}">Groups</a></li>
</%block>

<h1>Groups</h1>


<button class="img-button theme" type="button" onclick="location.href='${request.route_url('add_group')}'">
    <img src="${request.static_url('magpie.ui.home:static/add.png')}" alt="" class="icon-add">
    Add Group
</button>

<table class="simple-list" id="view_group_members_list">
<thead class="theme">
<tr>
    <th>Group</th>
    <th>Members count</th>
    <th>Action</th>
</tr>
</thead>
<tbody>
%for i, group in enumerate(group_names):
<form action="${request.path}" method="post">
%if i % 2:
<tr class="list-row-even">
%else:
<tr class="list-row-odd">
%endif
    <td><input type="hidden" value=${group} name="group_name">${group}</td>
    <td>${group_names[group]["members"]}</td>
    <td style="white-space: nowrap">
        <input type="submit" value="Edit" name="edit" class="button theme">
        <input value="Delete" name="delete"
            %if group in MAGPIE_FIXED_GROUP_EDITS:
                class="button delete disabled" type="button" disabled
            %else:
                class="button delete" type="submit"
            %endif
        >
    </td>
</tr>
</form>
%endfor
</tbody>
</table>
