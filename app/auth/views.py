from flask import render_template, redirect, request, url_for, flash
from flask.ext.login import login_user, logout_user, login_required, current_user
from . import auth
from .. import db
from ..models import User
from ..email import send_mail
from .forms import LoginForm, RegistrationForm

@auth.before_app_request
def before_request():
    if current_user.is_authenticated and not current_user.confirmed and request.endpoint[:5] != 'auth.' and request.endpoint != 'static':
        return redirect(url_for('auth.unconfirmed'))


@auth.route('/unconfirmed')
def unconfirmed():
	if current_user.is_anonymous or current_user.confirmed:
		return redirect('main.index')
	return render_template('auth/unconfirmed.html')


@auth.route('/login', methods=['GET', 'POST'])
def login():
	form = LoginForm()
	if form.validate_on_submit():
		user = User.query.filter_by(email=form.email.data).first()
		if user is not None and user.verify_password(form.password.data):
			login_user(user, form.remember_me.data)
			return redirect(request.args.get('next') or url_for('main.index'))
		flash('Usuário ou senha inválidos')
	return render_template('auth/login.html', form=form)


@auth.route('/logout')
@login_required
def logout():
	logout_user()
	flash('Você saiu com sucesso!')
	return redirect(url_for('main.index'))


@auth.route('/register', methods=['GET', 'POST'])
def register():
	form = RegistrationForm()
	if form.validate_on_submit():
		user = User(email=form.email.data,
					username=form.username.data,
					password=form.password.data)
		db.session.add(user)
		db.session.commit()
		token = user.generate_confirmation_token()
		send_mail(user.email, 'Confirme sua conta', 'auth/email/confirm', user=user, token=token)
		flash('Foi enviado um email de confirmação de cadastro pra você.')
		return redirect(url_for('main.index'))
	return render_template('auth/register.html', form=form)

@auth.route('/confirm/<token>')
@login_required
def confirm(token):
	if current_user.confirmed:
		return redirect(url_for('main.index'))
	if current_user.confirm(token):
		flash('Você confirmou sua conta com sucesso! Obrigado!')
	else:
		flash('O link de confirmação é invalido ou ja expirou.')
	return redirect(url_for('main.index'))

@auth.route('/confirm')
@login_required
def resend_confirmation():
	token = current_user.generate_confirmation_token()
	send_mail(current_user.email, 'Confirme sua conta', 'auth/email/confirm', user=current_user, token=token)
	flash('Foi enviado um email de confirmação de cadastro pra você.')
	return redirect(url_for('main.index'))

