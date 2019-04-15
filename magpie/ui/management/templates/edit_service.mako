<%inherit file="ui.management:templates/tree_scripts.mako"/>
<%namespace name="tree" file="ui.management:templates/tree_scripts.mako"/>

<%def name="render_item(key, value, level)">
    % if level > 0:
        <div class="tree_button"><input type="submit" value="Delete" name="delete_child" class="button delete"></div>
    % else:
        <div class="tree_button"><input type="submit" value="Delete" name="delete_child" class="button disabled" disabled></div>
    % endif
    % if "id" in value.keys():
        % if int(value["id"]) in resources_id_type.keys():
            % if not resources_id_type[int(value["id"])] in resources_no_child:
                <div class="tree_button"><input type="submit" value="Add child" name="add_child"></div>
            % else:
                <div class="tree_button"><input type="submit" value="Add child" name="add_child" class="button disabled" disabled></div>
            % endif
        % elif not service_no_child:
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
    <h3 class="alert_title danger">Danger!</h3>
    <p>
        Delete: [${service_name}]
    </p>
    <p>
        This operation will remove the service and all its sub-resources.
        This operation is not reversible.
    </p>
    <p>Continue?</p>
    <form action="${request.path}" method="post">
        %if service_push_show:
            <div class="checkbox_align">
                <label for="push_phoenix_checkbox_warning">
                    <input type="checkbox" name="service_push" id="push_phoenix_checkbox_warning" checked/>
                    <span>Push to Phoenix?</span>
                </label>
            </div>
        %endif
        <div>
            <input type="submit" class="button delete" name="delete" value="Delete"
                   onclick="this.parentElement.style.display="none";">
            <input type="submit" class="button cancel"name="cancel" value="Cancel"
                   onclick="this.parentElement.style.display="none";">
        </div>
    </form>
</div>

<script>
    function adjustWidth(id) {
        var x = document.getElementById(id);
        if (x.value.length > 20)
            x.size = x.value.length;
        else
            x.size = 20;
    }
</script>

<!-- since checkbox 'not checked' state is not actually sent,
     apply 'off' to force return of the checkbox's state on submit -->
<script type="text/javascript">
    $(document).ready(function() {
        $("#form_edit_service").on('submit', function() {
            $(this + 'input[type=checkbox]:not(:checked)').each(function () {
                $(this).attr('checked', true).val(0);
            });
        })
    })
</script>

<form action="${request.path}" method="post">
    <div class="panel_box">
        <div class="panel_heading">
            <span class="panel_title">Service: </span>
            <span class="panel_value">${service_name}</span>
            <span class="panel_heading_button">
                <input type="button" value="Remove Service" class="button delete"
                       onclick="$('#EditService_DeleteAlert').show();">
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
                            <input type="text" value="${service_name}" name="new_svc_name"
                                   id="input_name" onkeyup="adjustWidth('input_name')">
                            <input type="submit" value="Save" name="save_name">
                            <input type="submit" value="Cancel" name="no_edit">
                        %else:
                            <span class="panel_value">${service_name}</span>
                            <input type="submit" value="Edit" name="edit_name">
                        %endif
                    </p>
                    <p class="panel_line">
                        <span class="panel_entry">Protected URL: </span>
                        %if edit_mode == "edit_url":
                            <input type="text" value="${service_url}" name="new_svc_url"
                                   id="input_url" onkeyup="adjustWidth('input_url')">
                            <input type="submit" value="Save" name="save_url">
                            <input type="submit" value="Cancel" name="no_edit">
                        %else:
                            <a href="${service_url}" class="panel_value">${service_url}</a>
                            <input type="submit" value="Edit" name="edit_url">
                        %endif
                    </p>
                    <p class="panel_line">
                        <span class="panel_entry">Public URL: </span>
                        <a href="${public_url}" class="panel_value">${public_url}</a>
                    </p>
                    <p class="panel_line">
                        <span class="panel_entry">Type: </span>
                        <span class="label info">${cur_svc_type}</span>
                    </p>
                    <p class="panel_line">
                        <span class="panel_entry">Permissions: </span>
                        %for perm in service_perm:
                            <span class="label warning">${perm}</span>
                        %endfor
                    </p>
                    <p class="panel_line">
                        <span class="panel_entry">ID: </span>
                        <span class="panel_value">${service_id}</span>
                    </p>
                    %if service_push_show:
                        <div class="checkbox_align">
                            <label for="push_phoenix_checkbox_details">
                                <input type="hidden" name="service_push" value="off"/>
                                %if service_push:
                                    <input type="checkbox" name="service_push"
                                           id="push_phoenix_checkbox_details" checked/>
                                %else:
                                    <input type="checkbox" name="service_push"
                                           id="push_phoenix_checkbox_details"/>
                                %endif
                                <span>Push updates to Phoenix?</span>
                            </label>
                        </div>
                    %endif
                </div>
            </div>

            <div class="panel_box">
                <div class="panel_heading">
                    <div class="panel_title">Resources</div>
                </div>
                <div>
                    <div class="clear"></div>
                    <div class="tree">
                        ${tree.render_tree(render_item, resources)}
                    </div>
                </div>
            </div>
        </div>
    </div>
</form>
