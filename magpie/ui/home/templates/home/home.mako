<html>
<head>
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
    <title></title>
    <script type="text/javascript" src="https://ajax.googleapis.com/ajax/libs/jquery/1.5.2/jquery.min.js"></script>
</head>

<h3>Welcome to Magpie</h3>

<button type="button" onclick="location.href='./login'">Sign In!</button>

%if user_name:
<p>You are logged in as: ${ user_name }</p>
<form action="${request.registry.settings['magpie.url']}/signout" method="get">
    <!-- "came_from", "password" and "login" can all be overwritten -->
    <input type="hidden" value="${request.path_url}" name="came_from" id="came_from">
    <input type="submit" value="Sign Out" name="signout" id="submit">
</form>
% else:
<p>You are not logged in!</p>
% endif

<a href="register">registration</a></br>
<a href="users">Edit Users</a></br>
<a href="groups">Edit Groups</a></br>
<a href="service_manager">service_manager</a></br>


                                                                                                                                                                                <body>
<ul>
    <li><span class="Collapsable">item 1</span><ul>
        <li><span class="Collapsable">item 1</span></li>
        <li><span class="Collapsable">item 2</span><ul>
            <li><span class="Collapsable">item 1</span></li>
            <li><span class="Collapsable">item 2</span></li>
            <li><span class="Collapsable">item 3</span></li>
            <li><span class="Collapsable">item 4</span></li>
        </ul>
        </li>
        <li><span class="Collapsable">item 3</span></li>
        <li><span class="Collapsable">item 4</span><ul>
            <li><span class="Collapsable">item 1</span></li>
            <li><span class="Collapsable">item 2</span></li>
            <li><span class="Collapsable">item 3</span></li>
            <li><span class="Collapsable">item 4</span></li>
        </ul>
        </li>
    </ul>
    </li>
    <li><span class="Collapsable">item 2</span><ul>
        <li><span class="Collapsable">item 1</span></li>
        <li><span class="Collapsable">item 2</span></li>
        <li><span class="Collapsable">item 3</span></li>
        <li><span class="Collapsable">item 4</span></li>
    </ul>
    </li>
    <li><span class="Collapsable">item 3</span><ul>
        <li><span class="Collapsable">item 1</span></li>
        <li><span class="Collapsable">item 2</span></li>
        <li><span class="Collapsable">item 3</span></li>
        <li><span class="Collapsable">item 4</span></li>
    </ul>
    </li>
    <li><span class="Collapsable">item 4</span></li>
</ul>
</html>
<script type="text/javascript">
    $(".Collapsable").click(function () {
        $(this).parent().children().toggle();
        $(this).toggle();

    });

</script>