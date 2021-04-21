<%doc>
    This is the default notification message sent by email for administrator approval.
    It is formatted using the Mako template library (https://www.makotemplates.org/).
    The email header MUST be provided (from, to, subject, content-type).

    Additional variables available to build the content are:

        user:           Pending user from registration submission, with associated details.
        email_user:     Value defined by MAGPIE_SMTP_USER to identify the sender of this email.
        email_from:     Value defined by MAGPIE_SMTP_FROM to identify the sender of this email.
        admin_email:    Administrator email as defined by MAGPIE_ADMIN_APPROVAL_EMAIL_RECIPIENT.
        magpie_url:     Application endpoint defined by MAGPIE_URL or derived configuration settings.
        approve_url:    Endpoint where the pending user registration will be approved when visited.
        refuse_url:     Endpoint where the pending user registration will be refused when visited.
        pending_url:    Endpoint where the pending user registration details can be viewed (Magpie UI).
        settings:       Application settings.

</%doc>

%if email_from:
From: ${email_from}
%else:
From: ${email_user}
%endif
To: ${admin_email}
Subject: Magpie User Registration requests Admin Approval
Content-Type: text/plain; charset=UTF-8

Dear administrator,

A new user account registration requires your attention.
Following are the details submitted by the user:

    Username:  ${user.user_name}
    Email:     ${user.email}

This registration was submitted at ${magpie_url}.
Please select the link with desired result regarding this request:

    Approve:   ${approve_url}

    Refuse:    ${refuse_url}


Approving will complete the registration process by notifying the user that its account was approved and created.
Refusing will dismiss the pending user registration completely.
Omitting to select any result will leave the registration pending for approval.

You can also visit ${pending_url} to complete this process using Magpie interface at a later time.

Regards,
${email_user}
