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
Content-Type: text/html; charset=UTF-8

<%doc> === end of header === </%doc>

<html lang="en">
    <head><title>Magpie User Registration requires Admin Approval</title></head>
    <body>
        <p>
        Dear administrator,
        </p>
        <p>
        A new user account registration requires your attention.<br>
        Following details were submitted by the user:<br>
        </p>

        <div style="margin-left: 1em">
            <table style="border: 1px solid; border-collapse: collapse;">
                <thead>
                <tr>
                    <th colspan="2" style="font-weight: bold">User Details</th>
                </tr>
                </thead>
                <tbody style="border: 1px solid; border-collapse: collapse;">
                <tr>
                    <td style="padding: 0.25em; font-weight: bold;">Username</td>
                    <td style="padding: 0.25em;">${user.user_name}</td>
                </tr>
                <tr>
                    <td style="padding: 0.25em; font-weight: bold;">Email</td>
                    <td style="padding: 0.25em;">${user.email}</td>
                </tr>
                </tbody>
            </table>
        </div>

        <p>
        This registration was submitted to <a href="${magpie_url}">${magpie_url}</a> on ${email_datetime}.<br>
        Please select the link with desired result regarding this request:
        </p>

        <div style="margin-left: 1em">
            <table style="border: 1px solid; border-collapse: collapse;">
                <tbody style="border: 1px solid; border-collapse: collapse;">
                <tr>
                    <td style="border: 1px solid; padding: 0.25em;"><a href="${approve_url}">Approve</a></td>
                    <td style="border: 1px solid; padding: 0.25em;"><a href="${decline_url}">Decline</a></td>
                </tr>
                </tbody>
            </table>
        </div>

        <p>
        Approving will complete the registration process by notifying the user that its account was created.<br>
        Declining will dismiss the pending user registration completely.<br>
        Omitting to select any result will leave the registration pending for approval.<br>
        </p>
        <p>
        You can also visit the <a href="${display_url}">Pending User Details</a> page to complete
        this process using Magpie interface at a later time.
        </p>

        Regards,<br>
        ${email_user}
    </body>
</html>
