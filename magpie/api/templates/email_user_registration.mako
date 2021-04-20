<%doc>
    This is the default notification message sent by email for user registration validation.
    It is formatted using the Mako template library (https://www.makotemplates.org/).
    The email header MUST be provided (from, to, subject, content-type).

    Additional variables available to build the content are:

        user:           Pending user from registration submission, with associated details.
        magpie_url:     Application endpoint defined by MAGPIE_URL or derived configuration.
        login_url:      Endpoint where login can be accomplished.
        valid_url:      Endpoint where email validation can be performed.
        settings:       Application settings.

</%doc>

From: Magpie
To: ${user.email}
Subject: User Registration to Magpie
Content-Type: text/plain; charset=UTF-8

Dear ${user.user_name},

Your account submitted at ${magpie_url} has been approved.
Please complete your registration by accessing ${valid_url}.

Following validation, you will be able to login using your credentials at ${login_url}.

Regards,
Magpie
