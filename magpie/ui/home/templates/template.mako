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
    <meta name="author" content=${MAGPIE_AUTHOR}>
    <meta name="title" content=${MAGPIE_TITLE}>
    <meta name="description" content=${MAGPIE_DESCRIPTION}>
    <meta name="version" content=${MAGPIE_VERSION}>
    <meta name="source" content=${MAGPIE_SOURCE_URL}>
    <script type="text/javascript" src="https://ajax.googleapis.com/ajax/libs/jquery/2.1.1/jquery.min.js"></script>
    <script type="text/javascript">
        <%include file="magpie.ui.management:templates/tree_scripts.js"/>
    </script>
    <!-- needs more work, some elements should be static such as resource-names -->
    <!--
    <script type="text/javascript">
        function googleTranslateElementInit() {
          new google.translate.TranslateElement(
              {pageLanguage: 'en', layout: google.translate.TranslateElement.InlineLayout.SIMPLE},
              "google_translate_element" // div element id
          );
        }
    </script>
    <script type="text/javascript" src="//translate.google.com/translate_a/element.js?cb=googleTranslateElementInit"></script>
    -->
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
            <div id="title-header">${MAGPIE_TITLE} ${MAGPIE_SUB_TITLE}</div>
        </a>
        <div style="float: right;">
            %if MAGPIE_LOGGED_USER:
                <button class="img-button theme" type="button"
                        onclick="location.href='${request.route_url('edit_current_user')}'">
                    <img src="${request.static_url('magpie.ui.home:static/account.png')}" alt="">
                    <meta name="author" content="https://www.flaticon.com/authors/becris">
                    <meta name="source" content="https://www.flaticon.com/free-icon/user_848043">
                    Account
                </button>
                <button class="img-button theme" type="button"
                        onclick="location.href='${request.route_url('logout')}'">
                    <img src="${request.static_url('magpie.ui.home:static/logout.png')}" alt="">
                    <meta name="author" content="https://www.flaticon.com/authors/those-icons">
                    <meta name="source" content="https://www.flaticon.com/free-icon/logout_2089702">
                    Log Out
                </button>
            %else:
                <button class="img-button theme" type="button"
                        onclick="location.href='${request.route_url('add_user')}'">
                    <img src="${request.static_url('magpie.ui.home:static/register-user.png')}" alt="">
                    <meta name="author" content="https://www.flaticon.com/authors/those-icons">
                    <meta name="source" content="https://www.flaticon.com/free-icon/login_2089700">
                    Register
                </button>
                <button class="img-button theme" type="button"
                        onclick="location.href='${request.route_url('login')}'">
                    <img src="${request.static_url('magpie.ui.home:static/login.png')}" alt="">
                    <meta name="author" content="https://www.flaticon.com/authors/those-icons">
                    <meta name="source" content="https://www.flaticon.com/free-icon/login_2089700">
                    Log In
                </button>
            %endif
        </div>
    </div>
    <div class="clear header-line"></div>
    <div class="header-section">
        <ul class="breadcrumb">
            <%block name="breadcrumb"/>
        </ul>
        %if MAGPIE_LOGGED_USER:
        <div class="logged">
            Logged in: <a href="${request.route_url('edit_current_user')}">${MAGPIE_LOGGED_USER}</a>
        </div>
        %endif
    </div>
    <div class="language" id="google_translate_element"></div>
</div>

<div class="content">
${self.body()}
</div>
<div class="version-box">
    <div class="version-title">Magpie Version: </div>
    <div class="label label-info version-tag">${MAGPIE_VERSION}</div>
</div>

</body>
</html>
