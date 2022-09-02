<%inherit file="magpie.ui.home:templates/template.mako"/>

<%block name="breadcrumb">
<li><a href="${request.route_url('home')}">Home</a></li>
<li><a href="${request.route_url('view_users')}">Users</a></li>
<li>
    <a href="${request.route_url('view_pending_user', user_name=user_name)}">
    Pending User [${user_name}]
    </a>
</li>
</%block>

<h1>Pending User Registration: [${user_name}]</h1>

<h3>User Information</h3>


<div class="panel-box">
    <div class="panel-heading theme">
        <form id="delete_user" action="${request.path}" method="post">
            <span class="panel-title">User: </span>
            <span class="panel-value">[${user_name}]</span>
            <span class="panel-heading-button">
                <button value="Delete" name="delete" type="submit" class="button delete">
                    <img src="${request.static_url('magpie.ui.home:static/delete.png')}" alt=""
                         class="icon-delete">
                    <meta name="author" content="https://www.flaticon.com/authors/those-icons">
                    <meta name="source" content="https://www.flaticon.com/free-icon/delete_2089743">
                    Delete
                </button>
            </span>
        </form>
    </div>
    <div class="panel-body">
        <div class="panel-box">
            <div class="panel-heading subsection">
                <div class="panel-title">Details</div>
            </div>
            <div class="panel-fields">
                <table class="panel-line">
                    <tr>
                        <td>
                            <span class="panel-entry">Username: </span>
                        </td>
                        <td>
                            <div class="panel-line-entry">
                                <label>
                                    <span class="panel-line-textbox">${user_name}</span>
                                </label>
                            </div>
                        </td>
                    </tr>
                    <tr>
                        <td>
                            <span class="panel-entry">Email: </span>
                        </td>
                        <td>
                            <form id="edit_email" action="${request.path}" method="post">
                                <div class="panel-line-entry">
                                    <label>
                                        <span class="panel-value">
                                            <a href="mailto:${email}">${email}</a>
                                        </span>
                                        <input type="submit" value="Edit" name="edit_email" class="button theme">
                                    </label>
                                </div>
                            </form>
                        </td>
                    </tr>
                    <tr>
                        <td>
                            <span class="panel-entry">Status: </span>
                        </td>
                        <td>
                            <div class="status-container">
                                <img title="User account pending approval or validation." class="icon-pending"
                                     alt="PENDING" src="${request.static_url('magpie.ui.home:static/pending.png')}"/>
                                <meta name="author" content="https://www.flaticon.com/authors/those-icons">
                                <meta name="source" content="https://www.flaticon.com/free-icon/history_2089770">
                            </div>
                        </td>
                    </tr>
                </table>
            </div>
        </div>

        <div class="panel-box">
            <div class="panel-heading subsection">
                <div class="panel-title">Management</div>
            </div>
            <div class="panel-fields">
                <table class="panel-line">
                    <!--- fixme: should have a way to regenerate a new email confirmation url? --->
                    <tr>
                        <td>
                            <span class="panel-entry">Registration: </span>
                        </td>
                        <td>
                            <div class="panel-line-entry">
                                %if approve_url:
                                    <form id="approve_registration" action="${request.path}" method="post">
                                        <input value="Approve" name="approve" type="submit" class="button theme">
                                    </form>
                                %else:
                                    <input value="Approve" name="approve" type="button"
                                           class="button theme disabled" disabled>
                                %endif
                            </div>
                        </td>
                        <td>
                            <div class="panel-line-entry">
                                %if decline_url:
                                    <form id="decline_registration" action="${request.path}" method="post">
                                        <input value="Decline" name="decline" type="submit" class="button delete">
                                    </form>
                                %else:
                                    <input value="Decline" name="decline" type="button"
                                           class="button delete disabled" disabled>
                                %endif
                            </div>
                        </td>
                    </tr>
                </table>
            </div>
        </div>
    </div>
</div>
