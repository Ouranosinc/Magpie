<%doc>
    This is the default notification message sent by email for user registration validation.
    (see options: MAGPIE_USER_REGISTRATION_ENABLED and MAGPIE_USER_REGISTRATION_SUBMISSION_EMAIL_TEMPLATE)

    It is formatted using the Mako template library (https://www.makotemplates.org/).
    The email header MUST be provided (from, to, subject, content-type).

    Additional variables available to build the content are:

        user:               Pending user from registration submission, with associated details.
        email_user:         Value defined by MAGPIE_SMTP_USER to identify the sender of this email.
        email_from:         Value defined by MAGPIE_SMTP_FROM to identify the sender of this email.
        email_sender:       Resolved value between MAGPIE_SMTP_FROM or MAGPIE_SMTP_USER sending this email.
        email_recipient:    Resolved email of the identity where to send the notification email.
        email_datetime:     Date and time (ISO-8601 UTC) when that email was generated.
        magpie_url:         Application endpoint defined by MAGPIE_URL or derived configuration.
        login_url:          Endpoint where login can be accomplished.
        confirm_url:        Endpoint where email confirmation can be performed to validate the email recipient.
        approval_required:  Boolean indicating if administrator approval will be required following email confirmation
                            (based on application settings with MAGPIE_USER_REGISTRATION_APPROVAL_ENABLED).

</%doc>

From: ${email_sender}
To: ${email_recipient}
Subject: User Registration to Magpie
Content-Type: text/html; charset=UTF-8

<%doc> === end of header === </%doc>

<html lang="en">
    <head><title>User Registration to Magpie</title></head>
    <body>
        <p>
        Dear ${user.user_name},
        </p>

        <p>
        Your new account request submitted to ${magpie_url} has been received.
        Please confirm your registration email by <a href="${confirm_url}">clicking this link</a>.
        </p>

        <p>
        %if approval_required:
        Following email validation, an administrator will review your profile for approval.<br>
        Another confirmation email will be sent to notify you when your profile is approved and ready to be used.<br>
        %else:
        Following email validation, you will be able to <a href="${login_url}">Login</a> using your credentials.<br>
        %endif
        </p>

        Regards,<br>
        ${email_user}
    </body>
</html>
