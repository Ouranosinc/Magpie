<%doc>
    This is the default notification message sent by email for group terms and conditions validation.

    It is formatted using the Mako template library (https://www.makotemplates.org/).
    The email header MUST be provided (from, to, subject, content-type).

    Additional variables available to build the content are:

        user:               User requested to join a group, with associated details.
        group_name:         Name of the group the user has been requested to join
        group_terms:        Text containing the group's Terms and Conditions
        email_user:         Value defined by MAGPIE_SMTP_USER to identify the sender of this email.
        email_from:         Value defined by MAGPIE_SMTP_FROM to identify the sender of this email.
        email_sender:       Resolved value between MAGPIE_SMTP_FROM or MAGPIE_SMTP_USER sending this email.
        email_recipient:    Resolved email of the identity where to send the notification email.
        email_datetime:     Date and time (ISO-8601 UTC) when that email was generated.
        magpie_url:         Application endpoint defined by MAGPIE_URL or derived configuration.
        confirm_url:        Endpoint where Terms and Condition confirmation can be performed to join the group.

</%doc>


From: ${email_sender}
To: ${email_recipient}
Subject: Magpie - '${group_name}' Group Terms and Conditions
Content-Type: text/html; charset=UTF-8

<%doc> === end of header === </%doc>

<html lang="en">
    <head><title>${group_name} group terms and conditions</title></head>
    <body>
        <p>
        Dear ${user.user_name},
        </p>

        <p>
        A request to ${magpie_url} has been submitted to join the '${group_name}' group.
        Before you can be assigned to the group, we need your consent to the group's Terms and Conditions.
        </p>

        <p style="font-weight: bold;">
            Terms and conditions:
        </p>
        <p style="margin-left: 40px; font-style: italic;">
            ${group_terms}
        </p>

        <p>
        Please confirm agreeing to the group's Terms and Conditions by <a href="${confirm_url}">clicking this link</a>.
        </p>

        Regards,<br>
        ${email_user}
    </body>
</html>
