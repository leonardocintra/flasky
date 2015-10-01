from flask.ext.wtf import Form
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms import ValidationError
from wtforms.validators import Required, Email, Length, Regexp, EqualTo
from ..models import User

class RegistrationForm(Form):
	email = StringField('Email', validators=[Required(), Length(1, 64), Email()])
	username = StringField('Usuário', validators=[Required(), Length(1, 64), 
		Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0, 
			'Nomes de usuário deve ter apenas letras, números, pontos ou sublinhados')])
	password = PasswordField('Senha', validators=[Required(), EqualTo('confirmPassword', message='As senhas devem corresponder.')])
	confirmPassword = PasswordField('Confirma senha', validators=[Required()])
	submit = SubmitField('Registrar')

	def validate_email(self, field):
		if User.query.filter_by(email=field.data).first():
			raise ValidationError('Esse email ja existe')

	def validate_username(self, field):
		if User.query.filter_by(username=field.data).first():
			raise ValidationError('Esse nome de usuário ja existe')


class LoginForm(Form):
	email = StringField('Email', validators=[Required(), Length(1, 64), Email()])
	password = PasswordField('Senha', validators=[Required()])
	remember_me = BooleanField('Lembrar minha senha')
	submit = SubmitField('Entrar')


class ChangePasswordForm(Form):
	old_password = PasswordField('Senha antiga', validators=[Required()])
	password = PasswordField('Nova senha', validators=[Required(), EqualTo('confirmPassword', message='As senhas devem corresponder.')])
	confirmPassword = PasswordField('Confirma senha', validators=[Required()])
	submit = SubmitField('Alterar minha senha')


class PasswordResetRequestForm(Form):
	email = StringField('Email', validators=[Required(), Length(1, 64), Email()])
	submit = SubmitField('Alterar email')
	

class PasswordResetForm(Form):
	email = StringField('Email', validators=[Required(), Length(1, 64), Email()])
	password = PasswordField('Nova senha', validators=[Required(), EqualTo('confirmPassword', message='As senhas devem corresponder.')])
	confirmPassword = PasswordField('Confirma senha', validators=[Required()])
	submit = SubmitField('Alterar senha')

	def validate_email(self, field):
		if User.query.filter_by(email=field.data).first() is None:
			raise ValidationError('Email não encontrado')


class ChangeEmailForm(Form):
	email = StringField('Novo email', validators=[Required(), Length(1, 64), Email()])
	password = PasswordField('Senha', validators=[Required()])
	submit = SubmitField('Atualizar meu email')

	def validate_email(self, field):
		if User.query.filter_by(email=field.data).first():
			raise ValidationError('Esse email ja esta cadastrado')