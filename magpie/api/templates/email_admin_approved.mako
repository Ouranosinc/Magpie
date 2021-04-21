<%doc>
    This is the default notification message sent by email to the user to notify of accepted administrator approval.
    It is formatted using the Mako template library (https://www.makotemplates.org/).
    The email header MUST be provided (from, to, subject, content-type).

    Additional variables available to build the content are:

        user:           Pending user from registration submission, with associated details.
        email_user:     Value defined by MAGPIE_SMTP_USER to identify the sender of this email.
        email_from:     Value defined by MAGPIE_SMTP_FROM to identify the sender of this email.
        magpie_url:     Application endpoint defined by MAGPIE_URL or derived configuration settings.
        login_url:      Endpoint where login can be accomplished.
        settings:       Application settings.

</%doc>

%if email_from:
From: ${email_from}
%else:
From: ${email_user}
%endif
To: ${user.email}
Subject: Magpie User Registration Approved
Content-Type: text/plain; charset=UTF-8

Dear ${user.user_name},

Your account request submitted at ${magpie_url} has been approved.
You should be able to login using your credentials at ${login_url}.

Regards,
${email_user}
