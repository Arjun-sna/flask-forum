# -*- coding: utf-8 -*-
"""
    flaskbb.auth.views
    ~~~~~~~~~~~~~~~~~~

    This view provides user authentication, registration and a view for
    resetting the password of a user if he has lost his password

    :copyright: (c) 2014 by the FlaskBB Team.
    :license: BSD, see LICENSE for more details.
"""
import logging
from datetime import datetime

from flask import Blueprint, current_app, flash, g, redirect, request, url_for, jsonify
from flask.views import MethodView
from flask_jwt_extended import create_access_token, get_jwt_identity, jwt_required, current_user
from flask_babelplus import gettext as _
from marshmallow.exceptions import ValidationError as DataError

from flaskbb.auth.forms import (
    AccountActivationForm,
    ForgotPasswordForm,
    LoginForm,
    LoginRecaptchaForm,
    ReauthForm,
    RegisterForm,
    RequestActivationForm,
    ResetPasswordForm,
)
from flaskbb.extensions import db, limiter
from flaskbb.utils.helpers import (
    anonymous_required,
    enforce_recaptcha,
    format_timedelta,
    get_available_languages,
    redirect_or_next,
    register_view,
    registration_enabled,
    render_template,
    requires_unactivated,
)
from flaskbb.utils.settings import flaskbb_config

from ..core.auth.authentication import StopAuthentication
from ..core.auth.registration import UserRegistrationInfo, UserRegistrationInputSchema
from ..core.exceptions import PersistenceError, StopValidation, ValidationError
from ..core.tokens import TokenError
from .plugins import impl
from .services import (
    account_activator_factory,
    authentication_manager_factory,
    reauthentication_manager_factory,
    registration_service_factory,
    reset_service_factory,
)

logger = logging.getLogger(__name__)
user_registration_info_schema = UserRegistrationInputSchema()


# class Logout(MethodView):
#     decorators = [limiter.exempt, login_required]

#     def get(self):
#         logout_user()
#         flash(_("Logged out"), "success")
#         return redirect(url_for("forum.index"))


class Login(MethodView):
    def __init__(self, authentication_manager_factory):
        self.authentication_manager_factory = authentication_manager_factory

    def post(self):
        credentials = request.get_json()
        auth_manager = self.authentication_manager_factory()
        try:
            token, user = auth_manager.authenticate(
                identifier=credentials['username'], secret=credentials['password']
            )
            return {'access_token': token[0], 'refresh_token': token[1]}, 200
        except StopAuthentication as e:
            logger.exception(e)
            return e.reason, 401


class Reauth(MethodView):
    decorators = [jwt_required(refresh=True), limiter.exempt]

    def __init__(self, reauthentication_factory):
        self.reauthentication_factory = reauthentication_factory

    def post(self):
        request_data = request.get_json()

        reauth_manager = self.reauthentication_factory()
        try:
            token, user = reauth_manager.reauthenticate(
                user=current_user
            )
            return {'access_token': token[0], 'refresh_token': token[1]}, 200
        except StopAuthentication as e:
            logger.exception(e)
            return e.reason, 401


class Register(MethodView):
    decorators = [anonymous_required, registration_enabled]

    def __init__(self, registration_service_factory):
        self.registration_service_factory = registration_service_factory

    def post(self):
        request_data = request.get_json()
        try:
            user = user_registration_info_schema.load(request_data)
            service = self.registration_service_factory()
            createdUser = service.register(user)
            return {'id': createdUser.id}
        except StopValidation as e:
            logger.exception(e)
            return jsonify(e.reasons), 422


class ForgotPassword(MethodView):

    def __init__(self, password_reset_service_factory):
        self.password_reset_service_factory = password_reset_service_factory

    def post(self):
        request_data = request.get_json()
        try:
            service = self.password_reset_service_factory()
            service.initiate_password_reset(request_data['email'])
        except ValidationError:
            return {'error': "You have entered an username or email address that "
                    "is not linked with your account."}, 422
        else:
            return {'success': True}, 200


class ResetPassword(MethodView):
    decorators = [anonymous_required]

    def __init__(self, password_reset_service_factory):
        self.password_reset_service_factory = password_reset_service_factory

    def post(self, token):
        request_data = request.get_json()
        try:
            service = self.password_reset_service_factory()
            service.reset_password(
                token, request_data['email'], request_data['password']
            )
        except TokenError as e:
            return jsonify(e.reason), 422
        except StopValidation as e:
            return jsonify(e.reasons), 401
        finally:
            try:
                db.session.commit()
            except Exception:
                logger.exception(
                    "Error while finalizing database when resetting password"  # noqa
                )
                db.session.rollback()

        return {'success': True}, 200


class RequestActivationToken(MethodView):

    def __init__(self, account_activator_factory):
        self.account_activator_factory = account_activator_factory

    def post(self):
        request_data = request.get_json()
        activator = self.account_activator_factory()
        try:
            activator.initiate_account_activation(request_data['email'])
        except ValidationError as e:
            return jsonify(e.reasons), 401
        else:
            return {'success': True}


class ActivateAccount(MethodView):

    def __init__(self, account_activator_factory):
        self.account_activator_factory = account_activator_factory

    def get(self, token):
        activator = self.account_activator_factory()

        try:
            activator.activate_account(token)
        except TokenError as e:
            return {'error': e.reason}, 422
        except ValidationError as e:
            return {'error': e.reason}, 422
        else:
            db.session.commit()
            return {'success': True}, 200


@impl(tryfirst=True)
def flaskbb_load_blueprints(app):
    auth = Blueprint("auth", __name__)

    def login_rate_limit():
        """Dynamically load the rate limiting config from the database."""
        # [count] [per|/] [n (optional)] [second|minute|hour|day|month|year]
        return "{count}/{timeout}minutes".format(
            count=flaskbb_config["AUTH_REQUESTS"],
            timeout=flaskbb_config["AUTH_TIMEOUT"]
        )

    def login_rate_limit_message():
        """Display the amount of time left until the user can access the requested
        resource again."""
        current_limit = getattr(g, 'view_rate_limit', None)
        if current_limit is not None:
            window_stats = limiter.limiter.get_window_stats(*current_limit)
            reset_time = datetime.utcfromtimestamp(window_stats[0])
            timeout = reset_time - datetime.utcnow()
        return "{timeout}".format(timeout=format_timedelta(timeout))

    @auth.before_request
    def check_rate_limiting():
        """Check the the rate limits for each request for this blueprint."""
        if not flaskbb_config["AUTH_RATELIMIT_ENABLED"]:
            return None
        return limiter.check()

    @auth.errorhandler(429)
    def login_rate_limit_error(error):
        """Register a custom error handler for a 'Too Many Requests'
        (HTTP CODE 429) error."""
        return render_template(
            "errors/too_many_logins.html", timeout=error.description
        )

    # Activate rate limiting on the whole blueprint
    limiter.limit(
        login_rate_limit, error_message=login_rate_limit_message
    )(auth)

    # register_view(auth, routes=['/logout'], view_func=Logout.as_view('logout'))
    register_view(
        auth,
        routes=['/login'],
        view_func=Login.as_view(
            'login',
            authentication_manager_factory=authentication_manager_factory
        )
    )
    register_view(
        auth,
        routes=['/reauth'],
        view_func=Reauth.as_view(
            'reauth',
            reauthentication_factory=reauthentication_manager_factory
        )
    )
    register_view(
        auth,
        routes=['/register'],
        view_func=Register.as_view(
            'register',
            registration_service_factory=registration_service_factory
        )
    )

    register_view(
        auth,
        routes=['/reset-password'],
        view_func=ForgotPassword.as_view(
            'forgot_password',
            password_reset_service_factory=reset_service_factory
        )
    )

    register_view(
        auth,
        routes=['/reset-password/<token>'],
        view_func=ResetPassword.as_view(
            'reset_password',
            password_reset_service_factory=reset_service_factory
        )
    )

    register_view(
        auth,
        routes=['/activate'],
        view_func=RequestActivationToken.as_view(
            'request_activation_token',
            account_activator_factory=account_activator_factory
        )
    )

    register_view(
        auth,
        routes=['/activate/confirm/<token>'],
        view_func=ActivateAccount.as_view(
            'autoactivate_account',
            account_activator_factory=account_activator_factory
        )
    )

    app.register_blueprint(auth, url_prefix=app.config['AUTH_URL_PREFIX'])
