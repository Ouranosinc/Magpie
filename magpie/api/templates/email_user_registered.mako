<%doc>
    This is the default notification message sent by email to the administrator following successful user registration.
    (see option: MAGPIE_USER_REGISTERED_ENABLED)

    It is formatted using the Mako template library (https://www.makotemplates.org/).
    The email header MUST be provided (from, to, subject, content-type).

    Additional variables available to build the content are:

        user:               User from registration submission, with associated details.
        email_user:         Value defined by MAGPIE_SMTP_USER to identify the sender of this email.
        email_from:         Value defined by MAGPIE_SMTP_FROM to identify the sender of this email.
        email_sender:       Resolved value between MAGPIE_SMTP_FROM or MAGPIE_SMTP_USER sending this email.
        email_recipient:    Resolved email of the identity where to send the notification email.
        magpie_url:         Application endpoint defined by MAGPIE_URL or derived configuration.
        login_url:          Endpoint where login can be accomplished.

</%doc>

From: ${email_sender}
To: ${email_recipient}
Subject: Magpie User Registration Completed
Content-Type: text/plain; charset=UTF-8

<%doc> === end of header === </%doc>

Dear administrator,

This notification email is to inform you that the following user as completed registration and email validation.

    Username: ${user.user_name}
    Email:    ${user.user_name}

Their account can be viewed at the following location: ${magpie_url}/ui/users/${user.user_name}/default
(Note: Login is required: ${login_url})

Regards,
${email_user}
