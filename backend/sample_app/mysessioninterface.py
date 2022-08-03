from flask.sessions import SecureCookieSessionInterface, SessionMixin
from itsdangerous import BadSignature


class MySessionInterface(SecureCookieSessionInterface):

    def save_session(
            self, app: "Flask", session: SessionMixin, response: "Response"
    ):
        name = self.get_cookie_name(app)
        domain = self.get_cookie_domain(app)
        path = self.get_cookie_path(app)
        secure = self.get_cookie_secure(app)
        samesite = self.get_cookie_samesite(app)
        httponly = self.get_cookie_httponly(app)

        # If the session is modified to be empty, remove the cookie.
        # If the session is empty, return without setting the cookie.
        if not session:
            if session.modified:
                response.delete_cookie(
                    name,
                    domain=domain,
                    path=path,
                    secure=secure,
                    samesite=samesite,
                    httponly=httponly,
                )

            return

        if not self.should_set_cookie(app, session):
            return

        expires = self.get_expiration_time(app, session)
        val = self.get_signing_serializer(app).dumps(dict(session))  # type: ignore
        response.set_cookie(
            name,
            val,  # type: ignore
            expires=expires,
            httponly=httponly,
            domain=domain,
            path=path,
            secure=secure,
            samesite=samesite,
        )

