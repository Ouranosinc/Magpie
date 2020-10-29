<%inherit file="magpie.ui.home:templates/template.mako"/>

<%block name="breadcrumb">
<li><a href="${request.route_url('home')}">Home</a></li>
<li><a href="${request.route_url('login')}">Log in</a></li>
</%block>

%if invalid_credentials:
<div class="alert alert-danger alert-visible" id="Login_CredentialsAlert">
    <h3 class="alert-title-danger">Invalid Credentials!</h3>
    <p>
        Incorrect username or password.
    </p>
    <form action="${request.path}" method="post">
        <input type="submit" class="button cancel" name="close" value="Close"
               onclick="this.parentElement.style.display='none';">
    </form>
</div>
%elif error:
<div class="alert alert-danger alert-visible" id="Login_ErrorFailureAlert">
    <h3 class="alert-title-danger">Login Error!</h3>
    <p>
        Login procedure generated an error.
    </p>
    <form action="${request.path}" method="post">
        <input type="submit" class="button cancel" name="close" value="Close"
               onclick="this.parentElement.style.display='none';">
    </form>
</div>
%endif

<h1>Log in</h1>

<form class="new-item-form" id="login_internal" action="${request.route_url('login')}" method="post">
    <h3>Magpie</h3>
    <input type="hidden" value="${request.route_url('home')}" name="came_from" id="came_from">
    <input type="hidden" value="ziggurat" name="provider_name">
    <table class="fields-table">
        <tr>
            <td>Username:</td>
            <td>
                <div class="input-container">
                <label>
                <input type="text" placeholder="username or email" name="user_name"
                       value="${user_name_internal}" class="equal-width">
                </label>
                </div>
            </td>
            <td><p class="alert-form-error">&nbsp;</p></td> <!-- empty cell to keep table shape consistent -->
        </tr>
        <tr>
            <td>Password:</td>
            <td>
                <div class="input-container">
                <label>
                <input type="password" placeholder="password" name="password" value="" class="equal-width">
                </label>
                </div>
            </td>
            <td><p class="alert-form-error">&nbsp;</p></td> <!-- empty cell to keep table shape consistent -->
        </tr>
        <tr>
            <td class="centered" colspan="2">
                <input class="button theme" type="submit" value="Sign In" name="submit" id="submit">
            </td>
        </tr>
    </table>
</form>


<form class="new-item-form" id="login_external" action="" method="post">
    <h3>External SignIn</h3>
    <input type="hidden" value="${request.route_url('home')}" name="came_from">
    <table class="fields-table">
        <tr>
            <td>Username:</td>
            <td>
                <label>
                <div class="input-container">
                    <input type="text" placeholder="external provider username" name="user_name"
                           value="${user_name_external}" class="equal-width">
                </div>
                </label>
            </td>
            <td><p class="alert-form-error">&nbsp;</p></td> <!-- empty cell to keep table shape consistent -->
        </tr>
        <tr>
            <td>Provider:</td>
            <td>
                <div class="input-container">
                <label>
                <select name="provider_name" class="equal-width">
                    %for provider in external_providers:
                        <option value="${provider}">${provider}</option>
                        %if provider == provider_name:
                        <option selected="selected">${provider}</option>
                        %endif
                    %endfor
                </select>
                </label>
                </div>
            </td>
            <td><p class="alert-form-error">&nbsp;</p></td> <!-- empty cell to keep table shape consistent -->
        </tr>
        <tr>
            <td class="centered" colspan="2">
                <input class="button theme" type="submit" value="Sign In" name="submit">
            </td>
        </tr>
    </table>
</form>



