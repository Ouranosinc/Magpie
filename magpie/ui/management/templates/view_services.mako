<%inherit file="ui.home:templates/template.mako"/>

<%block name="breadcrumb">
<li><a href="${request.route_url('home')}">Home</a></li>
<li><a href="${request.route_url('view_services', cur_svc_type=cur_svc_type)}">Services</a></li>
</%block>

<h1>Services</h1>

<button class="img_button" type="button" onclick="location.href='${request.route_url('add_service', cur_svc_type=cur_svc_type)}'">
    <img src="${request.static_url('ui.home:static/add.png')}">
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
            %for service in service_names:
                <form action="${request.path}" method="post">
                    <tr>
                        <td><input type="hidden" value=${service} name="service_name">${service}</td>
                        <td><input type="submit" value="Delete" name="delete"></td>
                        <td><input type="submit" value="Edit" name="edit"></td>
                    </tr>
                </form>
            %endfor
        </table>
    </div>
</div>



