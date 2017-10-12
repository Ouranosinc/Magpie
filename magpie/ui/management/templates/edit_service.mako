<%inherit file="ui.management:templates/tree_scripts.mako"/>
<%namespace name="tree" file="ui.management:templates/tree_scripts.mako"/>

<%def name="render_item(key, value, level)">
    % if level > 0:
        <div class="tree_button"><input type="submit" value="Delete" name="delete_child" class="button delete"></div>
    % else:
        <div class="tree_button"><input type="submit" value="Delete" name="delete_child" class="button disabled" disabled></div>
    % endif
    % if 'id' in value.keys():
        % if int(value['id']) in resources_id_type.keys():
            % if not resources_id_type[int(value['id'])] in resources_no_child:
                <div class="tree_button"><input type="submit" value="Add child" name="add_child"></div>
            % else:
                <div class="tree_button"><input type="submit" value="Add child" name="add_child" class="button disabled" disabled></div>
            % endif
        % elif len(resources_types) > 0:
            <div class="tree_button"><input type="submit" value="Add child" name="add_child"></div>
        % else:
            <div class="tree_button"><input type="submit" value="Add child" name="add_child" class="button disabled" disabled></div>
        % endif
    % endif
</%def>

<%block name="breadcrumb">
<li><a href="${request.route_url('home')}">Home</a></li>
<li><a href="${request.route_url('view_services', cur_svc_type=cur_svc_type)}">Services</a></li>
<li><a href="${request.route_url('edit_service', service_name=service_name, service_url=service_url, cur_svc_type=cur_svc_type)}">${service_name}</a></li>
</%block>

<div class="alert danger" id="EditService_DeleteAlert">
    <form action="${request.path}" method="post">
        <input type="submit" id="EditService_DeleteConfirm" name="delete" value="Delete" style="display:none;">
    </form>
    <label class="alert_button" onclick="this.parentElement.style.display='none';" for="EditService_DeleteConfirm">&check;</label>
    <span class="alert_button" onclick="this.parentElement.style.display='none';">&times;</span>
    <strong>Danger!</strong>
    <p>
        This operation will remove the service and all its sub-resources.
        This operation is not reversable.
    </p>
    <p>Continue?</p>
</div>

<form action="${request.path}" method="post">
    <div class="panel_box">
        <div class="panel_heading">
            <span class="panel_title">Service: </span>
            <span class="panel_value">${service_name}</span>
            <span class="panel_heading_button">
                <input type="button" value="Remove Service" onclick="$('#EditService_DeleteAlert').show();" class="button delete">
            </span>
        </div>
        <div class="panel_body">
            <div class="panel_box">
                <div class="panel_heading">
                    <div class="panel_title">Details</div>
                </div>
                <div>
                    <p class="panel_line">
                        <span class="panel_entry">Name: </span>
                        %if edit_mode == 'edit_name':
                            <input type="text" value="${service_name}" name="new_svc_name">
                            <input type="submit" value="Save" name="save_name">
                            <input type="submit" value="Cancel" name="no_edit">
                        %else:
                            <span class="panel_value">${service_name}</span>
                            <input type="submit" value="Edit" name="edit_name">
                        %endif
                    </p>
                    <p class="panel_line">
                        <span class="panel_entry">URL: </span>
                        %if edit_mode == 'edit_url':
                            <input type="text" value="${service_url}" name="new_svc_url">
                            <input type="submit" value="Save" name="save_url">
                            <input type="submit" value="Cancel" name="no_edit">
                        %else:
                            <span class="panel_value">${service_url}</span>
                            <input type="submit" value="Edit" name="edit_url">
                        %endif
                    </p>
                    <p class="panel_line">
                        <span class="panel_entry">Type: </span>
                        <span class="label info">${cur_svc_type}</span>
                    </p>
                    <p class="panel_line">
                        <span class="panel_entry">Permissions: </span>
                        <span class="panel_value">${service_perm}</span>
                    </p>
                    <p class="panel_line">
                        <span class="panel_entry">ID: </span>
                        <span class="panel_value">${service_id}</span>
                    </p>
                </div>
            </div>

            <div class="panel_box">
                <div class="panel_heading">
                    <div class="panel_title">Resources</div>
                </div>
                <div>
                    <div class="clear"/>
                    <div class="tree">
                        ${tree.render_tree(render_item, resources)}
                    </div>
                </div>
            </div>
        </div>
    </div>
</form>
