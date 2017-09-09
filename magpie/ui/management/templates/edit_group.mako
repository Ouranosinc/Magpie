<%inherit file="home:templates/template.mako"/>

<%block name="style">
li.Expanded {
    list-style-image: url('${request.static_url('home:static/ArrowExpanded.jpg')}');
}

li.Collapsed {
    list-style-image: url('${request.static_url('home:static/ArrowCollapsed.jpg')}');
}
</%block>


<%block name="script">
    $(".Collapsable").click(function () {
        var collapsable = $(this);
        var parent_div = $(this).parent();
        var li = parent_div.parent();
        var form = li.parent();
        var next_elem = form.next();

        if (next_elem.length == 1 && next_elem[0].tagName == 'UL') {
            var cur_class = li.attr("class");
            if (cur_class == "Collapsed") {
                li.attr("class", "Expanded");
            } else {
                li.attr("class", "Collapsed");
            }
            next_elem.children().toggle();
        }
    });
</%block>

<%def name="render_tree(tree)">
    <ul>
     %for key in tree:
        <div class="clear"/>
        <form id="edit_perm_${tree[key]['id']}" action="${request.path}" method="post">
            <li class="Expanded">
                <div class="tree_item"><span class="Collapsable">${key}</span></div>
                <input type="hidden" value=${tree[key]['id']} name="perm_id">
                %for perm in permissions:
                    % if perm in tree[key]['permission_names']:
                    <div class="perm_checkbox"><input type="checkbox" value="${perm}" name="permission" onchange="document.getElementById('edit_perm_${tree[key]['id']}').submit()" checked></div>
                    % else:
                    <div class="perm_checkbox"><input type="checkbox" value="${perm}" name="permission" onchange="document.getElementById('edit_perm_${tree[key]['id']}').submit()"></div>
                    % endif
                %endfor
            </li>
        </form>
        % if tree[key]['children']:
            ${render_tree(tree[key]['children'])}
        % endif
     %endfor
    </ul>
</%def>

<%block name="breadcrumb">
<li><a href="${request.route_url('home')}">Home</a></li>
<li><a href="${request.route_url('view_groups')}">Groups</a></li>
<li><a href="${request.route_url('edit_group', group_name=group_name, cur_svc_type=cur_svc_type)}">Group ${group_name}</a></li>
</%block>

<h1>Group ${group_name}</h1>

<h3>Members</h3>

<form id="edit_members" action="${request.path}" method="post">
<table>
%for user in users:
<tr>
    % if user in members:
    <td><input type="checkbox" value="${user}" name="member" onchange="document.getElementById('edit_members').submit()"checked>${user}</td>
    % else:
    <td><input type="checkbox" value="${user}" name="member" onchange="document.getElementById('edit_members').submit()">${user}</td>
    % endif
</tr>
%endfor
</table>
</form>

<h3>Permissions</h3>

<div class="tabs_panel">

    %for svc_type in svc_types:
        % if cur_svc_type == svc_type:
            <a class="current_tab" href="${request.route_url('edit_group', group_name=group_name, cur_svc_type=svc_type)}">${svc_type}</a>
        % else:
            <a class="tab" href="${request.route_url('edit_group', group_name=group_name, cur_svc_type=svc_type)}">${svc_type}</a>
        % endif
    %endfor

    <div class="current_tab_panel">
        <div class="clear"/>
        <div class="tree_header">
        <div class="tree_item">Resources</div>
        %for perm in permissions:
            <div class="perm_title">${perm}</div>
        %endfor
        </div>
        <div class="tree">
            ${render_tree(resources)}
        </div>
    </div>
</div>