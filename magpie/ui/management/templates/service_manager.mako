<h2>Services Manager</h2>

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

