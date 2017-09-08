<%inherit file="home:templates/template.mako"/>

<%block name="breadcrumb">
<li><a href="${request.route_url('home')}">Home</a></li>
<li><a href="${request.route_url('view_groups')}">Groups</a></li>
<li><a href="${request.route_url('edit_group', group_name=group_name, cur_svc_type=cur_svc_type)}">Group ${group_name}</a></li>
</%block>

<%block name="script">
<script type="text/javascript">
    $(".Collapsable").click(function () {
        var collapsable = $(this);
        var parent_div = $(this).parent();
        var li = $(this).parent().parent();
        var next_elem = li.next();

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

</script>
</%block>

<h1>Group ${group_name}</h1>



<h3>Members</h3>

<form action="${request.path}" method="post">
<table>
%for user in users:
<tr>
    % if user in members:
    <td><input type="checkbox" value="${user}" name="member" checked>${user}</td>
    % else:
    <td><input type="checkbox" value="${user}" name="member">${user}</td>
    % endif
</tr>
%endfor
</table>
</form>

<h3>Permissions</h3>


%for svc_type in svc_types:
% if cur_svc_type == svc_type:
<a class="current_tab" href="${request.route_url('edit_group', group_name=group_name, cur_svc_type=svc_type)}">${svc_type}</a>
% else:
<a class="tab" href="${request.route_url('edit_group', group_name=group_name, cur_svc_type=svc_type)}">${svc_type}</a>
% endif
%endfor

<%def name="render_tree(tree)">
    <ul>
     %for key in tree:
        <div class="clear"/>
        <li class="Expanded">
            <div class="tree_item"><span class="Collapsable">${key}</span></div>
            %for perm in permissions:
            <div class="perm_checkbox"><input type="checkbox" value="${perm}" name="permission" checked></div>
            %endfor
        </li>
        % if tree[key]:
            ${render_tree(tree[key])}
        % endif
     %endfor
    </ul>
</%def>

<div class="clear"/>
<div class="tree_item">Resources</div>
%for perm in permissions:
    <div class="perm_checkbox">${perm}</div>
%endfor

<div class="tree">
${render_tree(resources)}
</div>