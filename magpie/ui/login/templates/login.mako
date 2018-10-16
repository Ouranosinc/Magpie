<%inherit file="ui.home:templates/template.mako"/>

<%block name="breadcrumb">
<li><a href="${request.route_url('home')}">Home</a></li>
<li><a href="${request.route_url('login')}">Log in</a></li>
</%block>

%if invalid_credentials:
<div class="alert danger visible" id="Login_CredentialsAlert">
    <h3 class="alert_title danger">Invalid Credentials!</h3>
    <p>
        Incorrect username or password.
    </p>
    <form action="${request.path}" method="post">
        <input type="submit" class="button cancel" name="close" value="Close"
               onclick="this.parentElement.style.display='none';">
    </form>
</div>
%elif error:
<div class="alert danger visible" id="Login_ErrorFailureAlert">
    <h3 class="alert_title danger">Login Error!</h3>
    <p>
        Login procedure generated an unhandled error.
    </p>
    <form action="${request.path}" method="post">
        <input type="submit" class="button cancel" name="close" value="Close"
               onclick="this.parentElement.style.display='none';">
    </form>
</div>
%endif

<h1>Log in</h1>

<form class="new_item_form" id="login_internal" action="${request.route_url('login')}" method="post">
    <h3>Magpie</h3>
    <input type="hidden" value="${request.route_url('home')}" name="came_from" id="came_from">
    <input type="hidden" value="ziggurat" name="provider_name">
    <table class="fields_table">
        <tr>
            <td>Username:</td>
            <div class="input_container">
                <td><input type="text" name="user_name" value="${user_name_internal}" class="equal_width"></td>
            </div>
            <td><p class="alert_form_error">&nbsp;</p></td> <!-- empty cell to keep table shape consistent -->
        </tr>
        <tr>
            <td>Password:</td>
            <div class="input_container">
                <td><input type="password" name="password" value="" class="equal_width"></td>
            </div>
            <td><p class="alert_form_error">&nbsp;</p></td> <!-- empty cell to keep table shape consistent -->
        </tr>
        <tr><td class="centered" colspan="2"><input type="submit" value="Sign In" name="submit" id="submit"></td></tr>
    </table>
</form>


<form class="new_item_form" id="login_external" action="" method="post">
    <h3>External SignIn</h3>
    <input type="hidden" value="${request.route_url('home')}" name="came_from">
    <table class="fields_table">
        <tr>
            <td>Username:</td>
            <div class="input_container">
                <td><input type="text" name="user_name" value="${user_name_external}" class="equal_width"></td>
            </div>
            <td><p class="alert_form_error">&nbsp;</p></td> <!-- empty cell to keep table shape consistent -->
        </tr>
        <tr>
            <td>Provider:</td>
            <div class="input_container">
                <td><select name="provider_name" class="equal_width">
                    %for provider in external_providers:
                        <option value="${provider}">${provider}</option>
                        %if provider == provider_name:
                        <option selected="selected">${provider}</option>
                        %endif
                    %endfor
                </select></td>
            </div>
            <td><p class="alert_form_error">&nbsp;</p></td> <!-- empty cell to keep table shape consistent -->
        </tr>
        <tr><td class="centered" colspan="2"><input type="submit" value="Sign In" name="submit"></td></tr>
    </table>
</form>



