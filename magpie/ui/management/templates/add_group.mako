<%inherit file="ui.home:templates/template.mako"/>

<%block name="breadcrumb">
<li><a href="${request.route_url('home')}">Home</a></li>
<li><a href="${request.route_url('view_groups')}">Groups</a></li>
<li><a href="${request.route_url('add_group')}">Add Group</a></li>
</%block>

<h1>Add Group</h1>

<form class="new_item_form" action="${request.path}" method="post">
    <input type="hidden" value="${request.route_url('home')}" name="came_from">
    <table class="fields_table">
        <tr>
            <td>Group name:</td>
            <td><input type="text" name="group_name" value="${form_group_name}"></td>
            %if conflict_group_name:
                <td><p class="alert_form_error">
                    <img src="${request.static_url('magpie.ui.home:static/warning_exclamation.png')}" /> Conflict </p>
                </td>
            %elif invalid_group_name:
                <td><p class="alert_form_error">
                    <img src="${request.static_url('magpie.ui.home:static/warning_exclamation.png')}" /> Invalid </p>
                </td>
            %else:
                <td><p class="alert_form_error">&nbsp;</p></td> <!-- empty cell to keep table shape consistent -->
            %endif
        </tr>
        <tr><td class="centered" colspan="2"><input type="submit" value="Add Group" name="create"></td></tr>
    </table>
</form>
