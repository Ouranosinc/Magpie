<%inherit file="ui.home:templates/template.mako"/>

<%block name="breadcrumb">
<li><a href="${request.route_url('home')}">Home</a></li>
<li><a href="${request.route_url('view_services', cur_svc_type=cur_svc_type)}">Services</a></li>
</%block>

%for service in service_names:
    <div class="alert danger" id="ViewService_DeleteAlert_${service}">
        <h3 class="alert_title danger">Danger!</h3>
        <p>
            Delete: [${service}]
        </p>
        <p>
            This operation will remove the service and all its sub-resources.
            This operation is not reversible.
        </p>
        <p>Continue?</p>
        <form action="${request.path}" method="post">
            <input type="hidden" value=${service} name="service_name">
            %if service_push_show:
                <div class="checkbox_align">
                    <label for="push_phoenix_checkbox_warning">
                        <input type="checkbox" name="service_push" checked="true" id="push_phoenix_checkbox_warning"/>
                        <span>Push to Phoenix?</span>
                    </label>
                </div>
            %endif
            <div>
                <input type="submit" class="button delete" name="delete" value="Delete"
                       onclick="this.parentElement.style.display='none';" >
                <input type="submit" class="button cancel" name="cancel" value="Cancel"
                       onclick="this.parentElement.style.display='none';" >
            </div>
        </form>
    </div>

    <script>
        function display_DeleteAlert_${service}() {
            %for sub_service in service_names:
                %if service == sub_service:
                    document.getElementById("ViewService_DeleteAlert_${sub_service}").style.display = "block";
                %else:
                    document.getElementById("ViewService_DeleteAlert_${sub_service}").style.display = "none";
                %endif
            %endfor
        }
    </script>
%endfor

%if service_push_show:
    <script>
        function display_PushPhoenix() {
            document.getElementById("ViewService_PushProcessingAlert").style.display = "block";
            document.getElementById("ViewService_PushSuccessAlert").style.display = "none";
            document.getElementById("ViewService_PushFailedAlert").style.display = "none";
        }
    </script>
    <div class="alert info" id="ViewService_PushProcessingAlert">
        <h3 class="alert_title info">Processing...</h3>
        <p>
            Syncing Phoenix services with Magpie services.
            This operation could take some time...
        </p>
    </div>

    %if service_push_success is not None:
        %if service_push_success:
           <div class="alert success visible" id="ViewService_PushSuccessAlert">
                <h3 class="alert_title success">Push to Phoenix successful</h3>
                <!-- <p>
                    Success.
                </p> -->
            </div>
        %else:
            <div class="alert warning visible" id="ViewService_PushFailedAlert">
                <h3 class="alert_title warning">Warning!</h3>
                <p>
                    Error occurred during Phoenix sync
                </p>
                <p> Common causes are:
                    <ul>
                    <li>Invalid login credentials</li>
                    <li>Down service</li>
                    <li>Error returned by GetCapabilities</li>
                    </ul>
                </p>
            </div>
        %endif
    %endif
%endif

<h1>Services</h1>


%if service_push_show:
    <form action="${request.path}" method="post" onsubmit="display_PushPhoenix()">
        <input type="submit" class="button warning" name="phoenix_push" value="Push to Phoenix">
        <!-- <input type="button" class="button warning" onclick="displayPushPhoenix()" value="Push to Phoenix">
        <input type="hidden" value="Submit">-->
    </form>
%endif
<button class="img_button" type="button" onclick="location.href='${request.route_url('add_service', cur_svc_type=cur_svc_type)}'">
    <img src="${request.static_url('magpie.ui.home:static/add.png')}">
    Add Service
</button>

<div class="tabs_panel">

    %for svc_type in svc_types:
        % if cur_svc_type == svc_type:
            <a class="current_tab" href="${request.route_url('view_services', cur_svc_type=svc_type)}">${svc_type}</a>
        % else:
            <a class="tab" href="${request.route_url('view_services', cur_svc_type=svc_type)}">${svc_type}</a>
        % endif
    %endfor

    <div class="current_tab_panel">
        <table class="simple_list_table">

            <tr>
                <th>Services</th>
                <th>Action</th>
            </tr>
            %for service in service_names:
                <form action="${request.path}" method="post">
                    <tr>
                        <td>
                            <input type="hidden" value=${service} name="service_name">${service}
                        </td>
                        <td style="white-space: nowrap">
                            <input type="submit" value="Edit" name="edit">
                            <input type="button" value="Delete" onclick="display_DeleteAlert_${service}()" class="button delete">
                        </td>
                    </tr>
                </form>
            %endfor
        </table>
    </div>
</div>



