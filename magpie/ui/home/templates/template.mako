<!DOCTYPE HTML>
<html lang="en">
<head>
    <title>Magpie</title>
    <meta charset="UTF-8">
    <link rel="stylesheet" type="text/css" href="//fonts.googleapis.com/css?family=Open+Sans" />
    <link href="${request.static_url('magpie.ui.home:static/settings.png')}"
          rel="shortcut icon" type="image/x-icon" />
    <link href="${request.static_url('magpie.ui.home:static/themes/{}.css'.format(MAGPIE_UI_THEME))}"
          rel="stylesheet" type="text/css" media="all" />
    <link href="${request.static_url('magpie.ui.home:static/style.css')}"
          rel="stylesheet" type="text/css" media="all" />
    <script type="text/javascript" src="https://ajax.googleapis.com/ajax/libs/jquery/1.5.2/jquery.min.js"></script>
    <style>
        <%block name="style"/>
    </style>
</head>
<body>

<div class="header">
    <div>
        <a href="${request.route_url('home')}">
            <div id="image-container">
                <div id="image-background">
                    <img src="${request.static_url('magpie.ui.home:static/settings_white.png')}" alt="">
                </div>
                <div id="image-overlay">
                    <img src="${request.static_url('magpie.ui.home:static/magpie.png')}" alt="">
                </div>
            </div>
            <div id="title-header">Magpie ${MAGPIE_SUB_TITLE}</div>
        </a>
        <div style="float: right;">
            %if MAGPIE_LOGGED_USER:
            <button class="img-button theme" type="button"
                    onclick="location.href='${request.route_url('edit_current_user')}'">Account</button>
            <button class="img-button theme" type="button"
                    onclick="location.href='${request.route_url('logout')}'">Log Out</button>
            %else:
            <button class="img-button theme" type="button"
                    onclick="location.href='${request.route_url('login')}'">Log In</button>
            %endif
        </div>
    </div>
    <div class="clear"></div>
    <div>
        <ul class="breadcrumb">
            <%block name="breadcrumb"/>
        </ul>
        %if MAGPIE_LOGGED_USER:
        <div style="float: right;">Logged in: <a href="${request.route_url('edit_current_user')}">${MAGPIE_LOGGED_USER}</a></div>
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
