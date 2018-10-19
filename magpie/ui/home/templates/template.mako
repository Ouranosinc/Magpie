<!DOCTYPE HTML>
<html>
<head>
    <title>Magpie Administration</title>
    <meta charset="UTF-8">
    <link rel="stylesheet" type="text/css" href="//fonts.googleapis.com/css?family=Open+Sans" />
    <link rel="shortcut icon" type="image/x-icon" href="${request.static_url('magpie.ui.home:static/settings.png')}" />
    <link href="${request.static_url('magpie.ui.home:static/style.css')}" rel="stylesheet" type="text/css" media="all" />
    <script type="text/javascript" src="https://ajax.googleapis.com/ajax/libs/jquery/1.5.2/jquery.min.js"></script>
    <style>
        <%block name="style"/>
    </style>
</head>
<body>

<div class="header">
    <div>
        <a href="${request.route_url('home')}">
            <div id="image_container">
                <div id="image_background"><img src="${request.static_url('magpie.ui.home:static/settings_white.png')}"></div>
                <div id="image_overlay"><img src="${request.static_url('magpie.ui.home:static/magpie.png')}"></div>
            </div>
            <div id="title_header">Magpie Administration</div>
        </a>
        <div style="float: right;">
            %if MAGPIE_LOGGED_USER:
            <button class="img_button" type="button" onclick="location.href='${request.route_url('logout')}'">Log Out</button>
            %else:
            <button class="img_button" type="button" onclick="location.href='${request.route_url('login')}'">Log In</button>
            %endif
        </div>
    </div>
    <div class="clear"></div>
    <div>
        <ul class="breadcrumb">
            <%block name="breadcrumb"/>
        </ul>
        %if MAGPIE_LOGGED_USER:
        <div style="float: right;">Logged in: ${MAGPIE_LOGGED_USER}</div>
        %endif
    </div>
</div>

<div class="content">
${self.body()}
</div>

</body>
</html>

<script type="text/javascript">
    <%block name="script"/>
</script>
