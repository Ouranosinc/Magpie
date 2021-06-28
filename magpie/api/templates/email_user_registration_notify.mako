<%doc>
    This is the default notification message sent by email to the administrator following successful user registration.
    (see options: MAGPIE_USER_REGISTRATION_NOTIFY_ENABLED and MAGPIE_USER_REGISTRATION_NOTIFY_EMAIL_TEMPLATE)

    It is formatted using the Mako template library (https://www.makotemplates.org/).
    The email header MUST be provided (from, to, subject, content-type).

    Additional variables available to build the content are:

        user:               User from registration submission, with associated details.
        email_user:         Value defined by MAGPIE_SMTP_USER to identify the sender of this email.
        email_from:         Value defined by MAGPIE_SMTP_FROM to identify the sender of this email.
        email_sender:       Resolved value between MAGPIE_SMTP_FROM or MAGPIE_SMTP_USER sending this email.
        email_recipient:    Resolved email of the identity where to send the notification email.
        email_datetime:     Date and time (ISO-8601 UTC) when that email was generated.
        magpie_url:         Application endpoint defined by MAGPIE_URL or derived configuration.
        login_url:          Endpoint where login can be accomplished.

</%doc>

From: ${email_sender}
To: ${email_recipient}
Subject: Magpie User Registration Completed
Content-Type: text/html; charset=UTF-8

<%doc> === end of header === </%doc>

<html lang="en">
    <head><title>Magpie User Registration Completed</title></head>
    <p>
        <p>
        Dear administrator,
        </p>
        <p>
        This notification email is to inform you that the following
        user has completed registration and email validation.
        </p>

        <div style="margin: 1em">
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
        Use this link to view their <a href="${magpie_url}/ui/users/${user.user_name}/default">User Account</a>.
        </p>
        <p>
        <b>Note:</b><br>
        <a href="${login_url}">Administrator Login</a> is required in the same browser to view user accounts.
        </p>

        Regards,<br>
        ${email_user}
    </body>
</html>
