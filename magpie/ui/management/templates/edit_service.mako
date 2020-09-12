<%inherit file="ui.management:templates/tree_scripts.mako"/>
<%namespace name="tree" file="ui.management:templates/tree_scripts.mako"/>

<%def name="render_item(key, value, level)">
    <div class="tree-button">
        <input type="submit" value="Delete" name="delete_child"
        %if level > 0:
               class="button delete"
        %else:
               class="button delete disabled" disabled
        %endif
        >
    </div>
    %if "id" in value.keys():
        <div class="tree-button">
            <input type="submit" value="Add child" name="add_child"
            %if int(value["id"]) in resources_id_type.keys():
                %if resources_id_type[int(value["id"])] in resources_no_child:
                    class="button theme disabled" disabled
                %else:
                    class="button theme"
                %endif
            %elif not service_no_child:
                    class="button theme"
            %else:
                class="button theme disabled" disabled
            % endif
            >
        </div>
    %endif
</%def>

<%block name="breadcrumb">
<li><a href="${request.route_url('home')}">
    Home</a></li>
<li><a href="${request.route_url('view_services', cur_svc_type=cur_svc_type)}">
    Services</a></li>
<li><a href="${request.route_url('edit_service', service_name=service_name, service_url=service_url, cur_svc_type=cur_svc_type)}">
    Service [${service_name}]</a></li>
</%block>

<div class="alert alert-danger" id="EditService_DeleteAlert">
    <h3 class="alert-title-danger">Danger!</h3>
    <p>
        <img src="${request.static_url('magpie.ui.home:static/exclamation-circle.png')}"
             alt="" class="icon-error" />
        Delete: [${service_name}]
    </p>
    <p>
        This operation will remove the service and all its sub-resources.
        This operation is not reversible.
    </p>
    <p>Continue?</p>
    <form action="${request.path}" method="post">
        %if service_push_show:
            <div class="checkbox-align">
                <label for="push_phoenix_checkbox_warning">
                    <input type="checkbox" name="service_push" id="push_phoenix_checkbox_warning" checked/>
                    <span>Push to Phoenix?</span>
                </label>
            </div>
        %endif
        <div>
            <input type="submit" class="button delete" name="delete" value="Delete"
                   onclick="this.parentElement.style.display='none';">
            <input type="submit" class="button cancel" name="cancel" value="Cancel"
                   onclick="this.parentElement.style.display='none';">
        </div>
    </form>
</div>

<script>
    function adjustWidth(id) {
        let x = document.getElementById(id);
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

<div class="panel-box">
    <div class="panel-heading theme">
        <span class="panel-title">Service: </span>
        <span class="panel-value">[${service_name}]</span>
        <span class="panel-heading-button">
            <input type="button" value="Remove Service" class="button delete"
                   onclick="$('#EditService_DeleteAlert').show();">
        </span>
    </div>
    <div class="panel-body">
        <div class="panel-box">
            <div class="panel-heading subsection">
                <div class="panel-title">Details</div>
            </div>
            <div>
                <form action="${request.path}" method="post">
                    <p class="panel-line">
                        <span class="panel-entry">Name: </span>
                        %if edit_mode == "edit_name":
                            <label>
                            <input type="text" value="${service_name}" name="new_svc_name"
                                   id="input_name" onkeyup="adjustWidth('input_name')">
                            <input class="button theme" type="submit" value="Save" name="save_name">
                            <input class="button cancel" type="submit" value="Cancel" name="no_edit">
                            </label>
                        %else:
                            <label>
                            <span class="panel-value">${service_name}</span>
                            <input class="button theme" type="submit" value="Edit" name="edit_name">
                            </label>
                        %endif
                    </p>
                </form>
                <form action="${request.path}" method="post">
                    <p class="panel-line">
                        <span class="panel-entry">Protected URL: </span>
                        %if edit_mode == "edit_url":
                            <label>
                            <input type="url" value="${service_url}" name="new_svc_url"
                                   id="input_url" onkeyup="adjustWidth('input_url')">
                            <input class="button theme" type="submit" value="Save" name="save_url">
                            <input class="button cancel" type="submit" value="Cancel" name="no_edit">
                            </label>
                        %else:
                            <label>
                            <a href="${service_url}" class="panel-value">${service_url}</a>
                            <input class="button theme" type="submit" value="Edit" name="edit_url">
                            </label>
                        %endif
                    </p>
                </form>
                <p class="panel-line">
                    <span class="panel-entry">Public URL: </span>
                    <a href="${public_url}" class="panel-value">${public_url}</a>
                </p>
                <p class="panel-line">
                    <span class="panel-entry">Type: </span>
                    <span class="label label-info">${cur_svc_type}</span>
                </p>
                <p class="panel-line">
                    <span class="panel-entry">Permissions: </span>
                    %for perm in service_perm:
                        <span class="label label-warning">${perm}</span>
                    %endfor
                </p>
                <p class="panel-line">
                    <span class="panel-entry">ID: </span>
                    <span class="panel-value">${service_id}</span>
                </p>
                %if service_push_show:
                    <div class="checkbox-align">
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

        <div class="panel-box">
            <div class="panel-heading subsection">
                <div class="panel-title">Resources</div>
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
