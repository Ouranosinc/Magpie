<%inherit file="ui.home:templates/template.mako"/>

<%block name="breadcrumb">
<li><a href="${request.route_url('home')}">Home</a></li>
<li><a href="${request.route_url('view_services', cur_svc_type=cur_svc_type)}">Services</a></li>
</%block>

%for i, service in enumerate(service_names):
    <div class="alert alert-danger" id="ViewService_DeleteAlert_Service_${i}">
        <h3 class="alert-title-danger">Danger!</h3>
        <p>
            Delete: [${service}]
        </p>
        <p>
            This operation will remove the service and all its sub-resources.
            This operation is not reversible.
        </p>
        <p>Continue?</p>
        <div>
        <form action="${request.path}" method="post">
            <input type="hidden" value=${service} name="service_name">
            %if service_push_show:
                <div class="checkbox-align">
                    <label for="push_phoenix_checkbox_warning">
                        <input type="checkbox" name="service_push" checked id="push_phoenix_checkbox_warning"/>
                        <span>Push to Phoenix?</span>
                    </label>
                </div>
            %endif
            <div class="alert-form-align">
                <input type="submit" class="button delete" name="delete" value="Delete"
                       onclick="document.getElementById('ViewService_DeleteAlert_Service_${i}').style.display='none';" >
            </div>
        </form>
        <div>
            <input type="submit" class="button cancel" name="cancel" value="Cancel"
                   onclick="document.getElementById('ViewService_DeleteAlert_Service_${i}').style.display='none';" >
        </div>
        </div>
    </div>

    <script>
        function display_DeleteAlert_Service_${i}() {
            %for j, sub_service in enumerate(service_names):
                let alert_${j} = document.getElementById("ViewService_DeleteAlert_Service_${j}");
                %if service == sub_service:
                    alert_${j}.style.display = "block";
                    alert_${j}.scrollIntoView();
                %else:
                    alert_${j}.style.display = "none";
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
    <div class="alert alert-info" id="ViewService_PushProcessingAlert">
        <h3 class="alert-title-info">Processing...</h3>
        <p>
            Syncing Phoenix services with Magpie services.
            This operation could take some time...
        </p>
    </div>

    %if service_push_success is not None:
        %if service_push_success:
           <div class="alert alert-success alert-visible" id="ViewService_PushSuccessAlert">
                <h3 class="alert-title-success">Push to Phoenix successful</h3>
                <!-- <p>
                    Success.
                </p> -->
            </div>
        %else:
            <div class="alert alert-warning alert-visible" id="ViewService_PushFailedAlert">
                <h3 class="alert-title-warning">Warning!</h3>
                <p>
                    Error occurred during Phoenix sync
                </p>
                <p> Common causes are: </p>
                <ul>
                    <li>Invalid login credentials</li>
                    <li>Down service</li>
                    <li>Error returned by GetCapabilities</li>
                </ul>
            </div>
        %endif
    %endif
%endif

<h1>Services</h1>


%if service_push_show:
    <form action="${request.path}" method="post" onsubmit="display_PushPhoenix()">
        <input type="submit" class="button-warning" name="phoenix_push" value="Push to Phoenix">
        <!-- <input type="button" class="button-warning" onclick="displayPushPhoenix()" value="Push to Phoenix">
        <input type="hidden" value="Submit">-->
    </form>
%endif
<button class="img-button theme" type="button"
        onclick="location.href='${request.route_url('add_service', cur_svc_type=cur_svc_type)}'">
    <img src="${request.static_url('magpie.ui.home:static/add.png')}" alt="">
    Add Service
</button>

<div class="tabs-panel">

    %for svc_type in svc_types:
        % if cur_svc_type == svc_type:
            <a class="current-tab" href="${request.route_url('view_services', cur_svc_type=svc_type)}">${svc_type}</a>
        % else:
            <a class="tab theme" href="${request.route_url('view_services', cur_svc_type=svc_type)}">${svc_type}</a>
        % endif
    %endfor

    <div class="current-tab-panel">
        <table class="simple-list">
            <thead class="theme">
            <tr>
                <th>Services</th>
                <th>Action</th>
            </tr>
            </thead>
            <tbody>
                %for i, service in enumerate(service_names):
                    <form action="${request.path}" method="post">
                    %if i % 2:
                    <tr class="list-row-even">
                    %else:
                    <tr class="list-row-odd">
                    %endif
                        <td>
                            <input type="hidden" value=${service} name="service_name">${service}
                        </td>
                        <td style="white-space: nowrap">
                            <input type="submit" value="Edit" name="edit" class="button theme">
                            <input type="button" value="Delete" class="button delete"
                                   onclick="display_DeleteAlert_Service_${i}()" >
                        </td>
                    </tr>
                    </form>
                %endfor
            </tbody>
        </table>
    </div>
</div>
