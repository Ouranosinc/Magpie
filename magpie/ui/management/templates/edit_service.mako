<%inherit file="ui.management:templates/tree_scripts.mako"/>
<%namespace name="tree" file="ui.management:templates/tree_scripts.mako"/>

<%def name="render_item(key, value, level)">
    % if level > 0:
        <div class="tree_button"><input type="submit" value="Delete" name="delete" class="delete_button"></div>
    % else:
        <div class="tree_button"><input type="submit" value="Delete" name="delete" class="disabled_button" disabled></div>
    % endif
    % if 'id' in value.keys():
        % if int(value['id']) in resources_id_type.keys():
            % if not resources_id_type[int(value['id'])] in resources_no_child:
                <div class="tree_button"><input type="submit" value="Add child" name="add_child"></div>
            % else:
                <div class="tree_button"><input type="submit" value="Add child" name="add_child" class="disabled_button" disabled></div>
            % endif
        % elif len(resources_types) > 0:
            <div class="tree_button"><input type="submit" value="Add child" name="add_child"></div>
        % else:
            <div class="tree_button"><input type="submit" value="Add child" name="add_child" class="disabled_button" disabled></div>
        % endif
    % endif
</%def>

<%block name="breadcrumb">
<li><a href="${request.route_url('home')}">Home</a></li>
<li><a href="${request.route_url('view_services', cur_svc_type=cur_svc_type)}">Services</a></li>
<li><a href="${request.route_url('edit_service', service_name=service_name, cur_svc_type=cur_svc_type)}">Service ${service_name}</a></li>
</%block>

<h1>Service ${service_name} Resources</h1>

<div class="clear"/>
<div class="tree">
    ${tree.render_tree(render_item, resources)}
</div>
