<%doc>
    This is the default notification message sent by email to the user to notify of accepted terms and conditions and
    to confirm the user has been added to the requested group.

    It is formatted using the Mako template library (https://www.makotemplates.org/).
    The email header MUST be provided (from, to, subject, content-type).

    Additional variables available to build the content are:

        user:               User requested to join a group, with associated details.
        group_name:         Name of the group the user has been requested to join
        email_user:         Value defined by MAGPIE_SMTP_USER to identify the sender of this email.
        email_from:         Value defined by MAGPIE_SMTP_FROM to identify the sender of this email.
        email_sender:       Resolved value between MAGPIE_SMTP_FROM or MAGPIE_SMTP_USER sending this email.
        email_recipient:    Resolved email of the identity where to send the notification email.
        email_datetime:     Date and time (ISO-8601 UTC) when that email was generated.
        magpie_url:         Application endpoint defined by MAGPIE_URL or derived configuration settings.

</%doc>

From: ${email_sender}
To: ${email_recipient}
Subject: Magpie - User ${user.user_name} added to '${group_name}' Group
Content-Type: text/plain; charset=UTF-8

<%doc> === end of header === </%doc>

Dear ${user.user_name},

The request to join the '${group_name}' group at ${magpie_url} has been completed, following your agreement of the terms and conditions.
Your account has been successfully added to the '${group_name}' group.

Regards,
${email_user}
