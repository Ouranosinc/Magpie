<%inherit file="ui.home:templates/template.mako"/>

<%block name="style">
li.Expanded {
    list-style-image: url('${request.static_url('ui.home:static/ArrowExpanded.jpg')}');
}

li.Collapsed {
    list-style-image: url('${request.static_url('ui.home:static/ArrowCollapsed.jpg')}');
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

<%def name="render_tree(tree, deletable)">
    <ul>
     %for key in tree:
        <div class="clear"/>
        <form id="resource_${tree[key]['id']}" action="${request.path}" method="post">
            <li class="Expanded">
                <div class="tree_item"><span class="Collapsable">${key}</span></div>
                <input type="hidden" value=${tree[key]['id']} name="resource_id">
                <div class="tree_button"><input type="submit" value="Add child" name="add_child"></div>
                % if deletable:
                    <div class="tree_button"><input type="submit" value="Delete" name="delete"></div>
                % endif
            </li>
        </form>
        % if tree[key]['children']:
            ${render_tree(tree[key]['children'], True)}
        % endif
     %endfor
    </ul>
</%def>

<%block name="breadcrumb">
<li><a href="${request.route_url('home')}">Home</a></li>
<li><a href="${request.route_url('view_services', cur_svc_type=cur_svc_type)}">Services</a></li>
<li><a href="${request.route_url('edit_service', service_name=service_name, cur_svc_type=cur_svc_type)}">Service ${service_name}</a></li>
</%block>

<h1>Service ${service_name} Resources</h1>

<div class="clear"/>
<div class="tree">
    ${render_tree(resources, False)}
</div>

