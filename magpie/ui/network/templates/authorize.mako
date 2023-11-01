<%inherit file="magpie.ui.home:templates/template.mako"/>

<form id="authorize_node_link"
      action="${authorize_uri}"
      class="new-item-form"
      method="get">
    <table class="authorization-table">
        <tr>
            <td>
                Magpie is requesting permission to link your account with the ${requesting_user_name} user's account
                on the Magpie instance named "${node_name}".
            </td>
        </tr>
        <tr>
            <td>
                <img title="This resource is absent from the remote server." class="icon-warning"
                     src="${request.static_url('magpie.ui.home:static/exclamation-triangle.png')}" alt="WARNING" />
                This will give this user full access to your account.
                <img title="This resource is absent from the remote server." class="icon-warning"
                     src="${request.static_url('magpie.ui.home:static/exclamation-triangle.png')}" alt="WARNING" />
            </td>
        </tr>
        <tr>
            <td>
                <input type="hidden" value="${token}" name="token">
                <input type="submit" value="Authorize" class="button theme centered">
            </td>
        </tr>
    </table>
</form>


