from flask import g, jsonify
from flask.ext.httpauth import HTTPBasicAuth
from ..models import User, AnonymousUser
from .errors import forbidden, unauthorized
from . import api


auth = HTTPBasicAuth()

@api.route('/token')
def get_token():
	if g.current_user.is_anonymous() or g.token_used:
		return unauthorized('Credenciais inválidas')
	return jsonify({'token': g.current_user.generate_auth_token(expiration=3600), 'expiration': 3600})

@auth.verify_password
def verify_password(email_or_token, password):
	if email_or_token == '':
		g.current_user = AnonymousUser()
		return True
	if password == '':
		g.current_user = User.verify_auth_token(email_or_token)
		g.token_used = True
		return g.current_user is not None
	user = User.query.filter_by(email=email_or_token).first()
	if not User:
		return False
	g.current_user = user
	g.token_used = False
	return user.verify_password(password)

@auth.error_handler
def auth_error():
	return unauthorized('Credenciais inválidas')

@api.before_request
@auth.login_required
def before_request():
	if not g.current_user.is_anonymous and not g.current_user.confirmed:
		return forbidden_error('Sua conta não foi confirmada')

