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

.current_tab a{
	color: #5E5E5E;
	line-height:1.5em;
	width:90%;
	margin:0 auto 2em;
}

a.current_tab:link, a.current_tab:visited {
    background-color: #f44336;
    color: white;
    padding: 14px 25px;
    text-align: center;
    text-decoration: none;
    display: inline-block;
}

a.tab:link, a.tab:visited {
    background-color: #ff43ff;
    color: white;
    padding: 14px 25px;
    text-align: center;
    text-decoration: none;
    display: inline-block;
}

a:hover, a:active {
    background-color: red;
}

.Collapsable input {
    float:left;
    padding: 5px 100px;
    border: 1px solid #eee;
}

li.Expanded {
    list-style-image: url('${request.static_url('management:static/ArrowExpanded.jpg')}');
}

li.Collapsed {
    list-style-image: url('${request.static_url('management:static/ArrowCollapsed.jpg')}');
}

div.tree_item {
    display:block;
    float:left;
}

div.perm_checkbox {
    display:block;
    width:5em;
    float:right;
}
.clear {
  clear: both;
}

li {
    border: 1px solid #dddddd;
}

li:nth-child(even) {
    background-color: #dddddd;
}

</style>

<script type="text/javascript" src="https://ajax.googleapis.com/ajax/libs/jquery/1.5.2/jquery.min.js"></script>
</head>


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

</body>
</html>

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