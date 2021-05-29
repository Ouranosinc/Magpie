<%doc>
    This is the default notification message sent by email for administrator approval.
    (see option: MAGPIE_ADMIN_APPROVAL_ENABLED)

    It is formatted using the Mako template library (https://www.makotemplates.org/).
    The email header MUST be provided (from, to, subject, content-type).

    Additional variables available to build the content are:

        user:               Pending user from registration submission, with associated details.
        email_user:         Value defined by MAGPIE_SMTP_USER to identify the sender of this email.
        email_from:         Value defined by MAGPIE_SMTP_FROM to identify the sender of this email.
        email_sender:       Resolved value between MAGPIE_SMTP_FROM or MAGPIE_SMTP_USER sending this email.
        email_recipient:    Resolved email of the identity where to send the notification email.
        email_datetime:     Date and time (ISO-8601 UTC) when that email was generated.
        magpie_url:         Application endpoint defined by MAGPIE_URL or derived configuration settings.
        approve_url:        Endpoint where the pending user registration request will be approved when visited.
        decline_url:        Endpoint where the pending user registration request will be declined when visited.
        pending_url:        Endpoint where the pending user registration details can be retrieved (Magpie API).
        display_url:        Endpoint where the pending user registration details can be viewed (Magpie UI).

</%doc>

From: ${email_sender}
To: ${email_recipient}
Subject: Magpie User Registration requires Admin Approval
Content-Type: text/plain; charset=UTF-8

<%doc> === end of header === </%doc>

Dear administrator,

A new user account registration requires your attention.
Following are the details submitted by the user:

    Username:  ${user.user_name}
    Email:     ${user.email}

This registration was submitted to ${magpie_url} on ${email_datetime}.
Please select the link with desired result regarding this request:

    <a href="${approve_url}">Approve</a>  |  <a href="${decline_url}">Decline</a>

Approving will complete the registration process by notifying the user that its account was approved and created.
Refusing will dismiss the pending user registration completely.
Omitting to select any result will leave the registration pending for approval.

You can also visit the <a href="${display_url}">Pending User Details</a> page to complete
this process using Magpie interface at a later time.

Regards,
${email_user}
