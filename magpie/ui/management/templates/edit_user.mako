<html>
<head>
<link href="${request.static_url('management:static/style.css')}" rel="stylesheet" type="text/css" media="all" />
<script type="text/javascript" src="https://ajax.googleapis.com/ajax/libs/jquery/1.5.2/jquery.min.js"></script>
</head>


<h1>User ${user_name}</h1>

<h3>Member of</h3>

<form action="${request.path}" method="post">
<table>
%for group in groups:
<tr>
    % if group in own_groups:
    <td><input type="checkbox" value="${group}" name="member" checked>${group}</td>
    % else:
    <td><input type="checkbox" value="${group}" name="member">${group}</td>
    % endif
</tr>
%endfor
</table>
</form>

</body>
</html>
