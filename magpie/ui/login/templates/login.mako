<%inherit file="home:templates/template.mako"/>

<%block name="breadcrumb">
<li><a href="${request.route_url('home')}">Home</a></li>
<li><a href="${request.route_url('login')}">Log in</a></li>
</%block>

<h1>Log in</h1>
<h3>Zigu</h3>
<form action="${request.path}" method="post">
    <!-- "came_from", "password" and "login" can all be overwritten -->
    <input type="hidden" value="${request.route_url('home')}" name="came_from" id="came_from">
    <!-- in the example above we changed the value of "login" to "username" -->
    <input type="hidden" value="ziggurat" name="provider_name">
    <input type="text" name="user_name">
    <input type="password" value="password" name="password">
    <input type="submit" value="Sign In" name="submit" id="submit">
</form>

<h3>External SignIn</h3>
<form action="" method="post">
    %for provider in external_provider:
        <input type="radio" name="provider_name" value="${provider}"/>${provider}</br>
    %endfor
    <input type="hidden" value="${request.route_url('home')}" name="came_from">
    <input type="text" name="user_name">
    <input type="submit" value="Sign In" name="submit">
</form>



