<%inherit file="magpie.ui.home:templates/template.mako"/>

<%block name="breadcrumb">
<li><a href="${request.route_url('home')}">Home</a></li>
<li><a href="${request.route_url('view_users')}">Users</a></li>
</%block>

<h1>Users</h1>

<button class="img-button theme" type="button" onclick="location.href='${request.route_url('add_user')}'">
    <img src="${request.static_url('magpie.ui.home:static/add.png')}" alt="" class="icon-add">
    Add User
</button>


<table class="simple-list" id="view_users_list">
<thead class="theme">
<tr>
    <th>User</th>
    <th>Status</th>
    <th>Action</th>
</tr>
</thead>
<tbody>
%for i, user_name in enumerate(users):
    <form action="${request.path}" method="post">
        %if i % 2:
        <tr class="list-row-even">
        %else:
        <tr class="list-row-odd">
        %endif
            <td><input type="hidden" value="${user_name}" name="user_name">${user_name}</td>
            <td>
                <div class="status-container">
                    %if user_name in users_with_error:
                        <img title="User account status has an issue." class="icon-warning" alt="USER_STATUS_ERROR"
                             src="${request.static_url('magpie.ui.home:static/exclamation-triangle.png')}"/>
                    %elif user_name in users_pending:
                        <img title="User account pending approval or validation." class="icon-pending" alt="PENDING"
                             src="${request.static_url('magpie.ui.home:static/pending.png')}"/>
                        <meta name="author" content="https://www.flaticon.com/authors/those-icons">
                        <meta name="source" content="https://www.flaticon.com/free-icon/history_2089770">
                    %else:
                        <img title="User account status is valid." class="icon-check" alt="OK"
                             src="${request.static_url('magpie.ui.home:static/checkmark-circle.png')}"/>
                    %endif
                </div>
            </td>
            <td style="white-space: nowrap">
                %if user_name in users_pending:
                    <input type="submit" value="View" name="view-pending" class="list-button button theme">
                %else:
                    <input type="submit" name="edit" class="list-button button theme"
                    %if user_name in MAGPIE_FIXED_USERS and user_name in MAGPIE_FIXED_USERS_REFS:
                        value="View"
                    %else:
                        value="Edit"
                    %endif
                    >
                %endif
                <input value="Delete"
                    %if user_name in MAGPIE_FIXED_USERS:
                       type="button" name="delete" class="list-button button delete disabled" disabled
                    %elif user_name in users_pending:
                       type="submit" name="delete-pending" class="list-button button delete"
                    %else:
                       type="submit" name="delete" class="list-button button delete"
                    %endif
                >
            </td>
        </tr>
    </form>
%endfor
</tbody>
</table>
