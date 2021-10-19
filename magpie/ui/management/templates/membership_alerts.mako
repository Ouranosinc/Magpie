<%def name="edit_membership_alerts()">
    %if edit_new_membership_error:
        <div class="alert alert-warning alert-visible" id="EditMembership_WarningFailureAlert">
            <h3 class="alert-title-warning">Warning</h3>
            <div class="alert-text-container alert-warning">
                <img src="${request.static_url('magpie.ui.home:static/exclamation-triangle.png')}"
                     alt="" class="icon-warning icon-color-white" />
                <div class="alert-text">
                    Edit Membership Failed
                </div>
            </div>
            <p>
                Failed to add the user to the group.
                Refer to the Magpie logs for more details.
            </p>
            <form action="${request.path}" method="get">
                <input type="submit" class="button cancel" name="close" value="Close"
                       onclick="this.parentElement.style.display='none';">
            </form>
        </div>
    %endif
    %if edit_membership_pending_success:
        <div class="alert alert-success alert-visible" id="EditMembership_SuccessAlert">
            <h3 class="alert-title-success">Success</h3>
            <div class="alert-text-container alert-success">
                <div class="alert-text">
                Edit Membership Successful
                </div>
            </div>
            <p>
                Successfully requested to add the user to the group.
                The terms and conditions of the group have been sent by email.
                The request will stay as 'pending' until confirmation of the terms and conditions is received.
            </p>
            <form action="${request.path}" method="get">
                <input type="submit" class="button cancel" name="close" value="Close"
                       onclick="this.parentElement.style.display='none';">
            </form>
        </div>
    %endif
</%def>
