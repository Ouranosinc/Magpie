<!DOCTYPE HTML>
<html>
<head>
<title>Magpie admin area</title>
<meta charset="UTF-8">
<link rel="shortcut icon" type="image/x-icon" href="${request.static_url('home:static/settings.png')}" />
<link href="${request.static_url('home:static/style.css')}" rel="stylesheet" type="text/css" media="all" />
<script type="text/javascript" src="https://ajax.googleapis.com/ajax/libs/jquery/1.5.2/jquery.min.js"></script>
</head>
<body>

<div class="header">
    <a href="/">
        <img src="${request.static_url('home:static/settings_white.png')}">
        Magpie Admin</a>
    %if logged_user:
        <button type="button" onclick="location.href='${request.route_url('logout')}'">Log out<br/>(${logged_user})</button>
    % else:
        <button type="button" onclick="location.href='${request.route_url('login')}'">Log In</button>
    % endif
    <div class="clear"></div>
    <ul class="breadcrumb">
        <%block name="breadcrumb"/>
    </ul>
</div>

<div class="content">
${self.body()}
</div>

</body>
</html>