<%inherit file="magpie.ui.management:templates/tree_scripts.mako"/>
<%namespace name="tree" file="magpie.ui.management:templates/tree_scripts.mako"/>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/10.4.0/styles/default.min.css">
<script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/10.4.0/highlight.min.js"></script>
<script charset="UTF-8" src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/10.4.0/languages/json.min.js"></script>
<script charset="UTF-8" src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/10.4.0/languages/yaml.min.js"></script>
<script>hljs.initHighlightingOnLoad();</script>


<%block name="breadcrumb">
<li><a href="${request.route_url('home')}">Home</a></li>
<li><a href="${request.route_url('view_services', cur_svc_type=cur_svc_type)}">Services</a></li>
<li>
    <a href="${request.route_url('edit_service', service_name=service_name, service_url=service_url, cur_svc_type=cur_svc_type)}">
    Service [${service_name}]
    </a>
</li>
</%block>

<div class="alert alert-danger" id="EditService_DeleteAlert">
    <h3 class="alert-title-danger">Danger!</h3>
    <div class="alert-text-container alert-danger">
        <img src="${request.static_url('magpie.ui.home:static/exclamation-circle.png')}"
             alt="" class="icon-error icon-color-invert" />
        <div class="alert-text">
        Delete: [${service_name}]
        </div>
    </div>
    <p>
        This operation will remove the service and all its sub-resources.
        This operation is not reversible.
    </p>
    <p>Continue?</p>
    <form action="${request.path}" method="post">
        %if service_push_show:
            <div class="checkbox-align">
                <label for="push_phoenix_checkbox_warning">
                    <input type="checkbox" name="service_push" id="push_phoenix_checkbox_warning" />
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


<div class="panel-box">
    <div class="panel-heading theme">
        <span class="panel-title">Service: </span>
        <span class="panel-value">[${service_name}]</span>
        <span class="panel-heading-button">
            <button type="button" value="Remove Service" class="button delete"
                   onclick="$('#EditService_DeleteAlert').show();">
                <img src="${request.static_url('magpie.ui.home:static/delete.png')}" alt="" class="icon-delete">
                <meta name="author" content="https://www.flaticon.com/authors/those-icons">
                <meta name="source" content="https://www.flaticon.com/free-icon/delete_2089743">
                Remove Service
            </button>
        </span>
    </div>
    <div class="panel-body">
        <div class="panel-box">
            <div class="panel-heading subsection">
                <div class="panel-title">Details</div>
            </div>
            <div class="panel-fields">
                <table class="panel-line">
                    <tr>
                        <td>
                            <span class="panel-entry">Name: </span>
                        </td>
                        <td>
                            <form action="${request.path}" method="post">
                                <div class="panel-line-entry">
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
                                </div>
                            </form>
                        </td>
                    </tr>
                    <tr>
                        <td>
                            <span class="panel-entry">Protected URL: </span>
                        </td>
                        <td>
                            <form action="${request.path}" method="post">
                                <div class="panel-line-entry">
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
                                </div>
                            </form>
                        </td>
                    </tr>
                    <tr>
                        <td>
                            <span class="panel-entry">Public URL: </span>
                        </td>
                        <td>
                            <div class="panel-line-entry">
                                <a href="${public_url}" class="panel-value">${public_url}</a>
                            </div>
                        </td>
                    </tr>
                    <tr>
                        <td>
                            <span class="panel-entry">Type: </span>
                        </td>
                        <td>
                            <div class="panel-line-entry">
                                <span class="label label-info">${cur_svc_type}</span>
                            </div>
                        </td>
                    </tr>
                    <tr>
                        <td>
                            <span class="panel-entry">Permissions: </span>
                        </td>
                        <td>
                            <div class="panel-line-entry">
                                %for perm in service_perm:
                                    <span class="label label-warning">${perm}</span>
                                %endfor
                            </div>
                        </td>
                    </tr>
                    <tr>
                        <td>
                            <span class="panel-entry">ID: </span>
                        </td>
                        <td>
                            <div class="panel-line-entry">
                                <span class="panel-value">${service_id}</span>
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
                        </td>
                    </tr>
                </table>
            </div>
        </div>

        %if service_configuration:
        <div class="panel-box">
            <div class="panel-heading subsection">
                <div class="panel-title">Configuration</div>
            </div>
            <div class="panel-message">
                <img src="${request.static_url('magpie.ui.home:static/info.png')}"
                     alt="INFO" class="icon-info alert-info" title="Service Configuration." />
                <meta name="source" content="https://commons.wikimedia.org/wiki/File:Infobox_info_icon.svg">
                <div class="panel-message-text">
                    This service employs the following custom configuration.
                </div>
            </div>
            <div class="clear"></div>
            <div class="panel-code-language">
                <script>
                    function show_language(language) {
                        let jsonButton = $("#button-json");
                        let yamlButton = $("#button-yaml");
                        let jsonConfig = $("#config-json");
                        let yamlConfig = $("#config-yaml");
                        if (language === "json") {
                            jsonButton.addClass("button-active");
                            yamlButton.removeClass("button-active");
                            jsonConfig.removeClass("hidden");
                            yamlConfig.addClass("hidden");
                        }
                        else if (language === "yaml") {
                            jsonButton.removeClass("button-active");
                            yamlButton.addClass("button-active");
                            jsonConfig.addClass("hidden");
                            yamlConfig.removeClass("hidden");
                        }
                    }
                </script>
                <div class="code-language-selector">
                    <input type="button" value="JSON" onclick="show_language('json')"
                           id="button-json" class="code-language-option button theme button-active">
                    <input type="button" value="YAML" onclick="show_language('yaml')"
                           id="button-yaml" class="code-language-option button theme">
                </div>
                <div class="current-code-language">
                    <!-- newlines matter between 'pre', they will add extra whitespace -->
                    <pre id="config-json"><code class="language-json">${service_config_json}</code></pre>
                    <pre id="config-yaml" class="hidden"><code class="language-yaml">${service_config_yaml}</code></pre>
                </div>
            </div>
        </div>
        %endif

        <div class="panel-box">
            <div class="panel-heading subsection">
                <div class="panel-title">Resources</div>
            </div>
            <div class="tree">
                ${tree.render_tree(render_item, resources)}
            </div>
        </div>
    </div>
</div>

<%def name="render_item(_, value, level)">
    <form id="resource_${value['id']}" action="${request.path}" method="post">
        <input type="hidden" value="${value['id']}" name="resource_id">
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
    </form>
</%def>
