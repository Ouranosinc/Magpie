<%inherit file="ui.home:templates/template.mako"/>

<%block name="style">
li.Expanded {
    list-style-image: url('${request.static_url('magpie.ui.home:static/ArrowExpanded.jpg')}');
}

li.Collapsed {
    list-style-image: url('${request.static_url('magpie.ui.home:static/ArrowCollapsed.jpg')}');
}
</%block>

<%block name="script">
    function toggle_subtree(li, target) {
        if (target.tagName == 'INPUT') {
            return;
        }
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
    }

    $(".Expanded").click(function(e) {
        toggle_subtree($(this), e.target);
    });

    $(".Collapsed").click(function(e) {
        toggle_subtree($(this), e.target);
    });
</%block>

<%def name="render_tree(item_renderer, tree, level = 0)">
    <ul>
     %for key in tree:
        <div class="clear"/>
        <form id="resource_${tree[key]['id']}_${tree[key].get('remote_id', '')}" action="${request.path}" method="post">
            % if tree[key]['children']:
            <li class="Expanded">
            % else:
            <li class="NoChild">
            % endif
                <div class="tree_item">${key}</div>
                <input type="hidden" value="${tree[key]['id']}" name="resource_id">
                <input type="hidden" value="${tree[key].get('remote_id', '')}" name="remote_id">
                <input type="hidden" value="${tree[key].get('matches_remote', '')}" name="matches_remote">
                ${item_renderer(key, tree[key], level)}
            </li>
        </form>
        % if tree[key]['children']:
            ${render_tree(item_renderer, tree[key]['children'], level + 1)}
        % endif
     %endfor
    </ul>
</%def>
