<%doc>
    This is the default notification message sent by email for user registration validation.
    It is formatted using the Mako template library (https://www.makotemplates.org/).
    The email header MUST be provided (from, to, subject, content-type).

    Additional variables available to build the content are:

        user:           Pending user from registration submission, with associated details.
        email_user:     Value defined by MAGPIE_SMTP_USER to identify the sender of this email.
        email_from:     Value defined by MAGPIE_SMTP_FROM to identify the sender of this email.
        magpie_url:     Application endpoint defined by MAGPIE_URL or derived configuration.
        login_url:      Endpoint where login can be accomplished.
        valid_url:      Endpoint where email validation can be performed.
        approval:       Boolean indicating if administrator approval will be required following validation.
        settings:       Application settings.

</%doc>

%if email_from:
From: ${email_from}
%else:
From: ${email_user}
%endif
To: ${user.email}
Subject: User Registration to Magpie
Content-Type: text/plain; charset=UTF-8

Dear ${user.user_name},

Your new account request submitted at ${magpie_url} has been received.
Please validate your registration email by visiting ${valid_url}.

%if approval:
Following email validation, an administrator will review your profile for approval.
Once approved, a confirmation email will be sent to notify you that your profile is ready to be used.
%else:
Following email validation, you will be able to login using your credentials at ${login_url}.
%endif

Regards,
${email_user}
