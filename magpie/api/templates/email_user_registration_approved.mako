<%doc>
    This is the default notification message sent by email to the user to notify of accepted administrator approval.
    (see options: MAGPIE_USER_REGISTRATION_APPROVAL_ENABLED and MAGPIE_USER_REGISTRATION_APPROVED_EMAIL_TEMPLATE)

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
        login_url:          Endpoint where login can be accomplished.

</%doc>

From: ${email_sender}
To: ${email_recipient}
Subject: Magpie User Registration Approved
Content-Type: text/plain; charset=UTF-8

<%doc> === end of header === </%doc>

Dear ${user.user_name},

Your account request submitted at ${magpie_url} has been approved.
You should be able to login using your credentials at ${login_url}.

Regards,
${email_user}
