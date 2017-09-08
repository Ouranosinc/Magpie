<%inherit file="home:templates/template.mako"/>

<%block name="breadcrumb">
<li><a href="${request.route_url('home')}">Home</a></li>
<li><a href="${request.route_url('view_services')}">Services</a></li>
</%block>

<h1>Services</h1>


<form action="${request.path}" method="post">
    service name (unique): <input type="text" value="" name="service_name" placeholder="emu">
    </br>
    service url: <input type="text" value="" name="service_url" placeholder="http://localhost:8093">
    </br>
    service type:
    %for service_type in service_types:
        <input type="radio" name="service_type" value="${service_type}"> ${service_type}
    %endfor
    </br>
    <input type="submit" value="register" name="register">
</form>

