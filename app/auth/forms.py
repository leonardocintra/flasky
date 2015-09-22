from flask.ext.wtf import Form
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import Required, Email, Length

class LoginForm(Form):
	email = StringField('Email', validators=[Required(), Length(1, 64), Email()])
	password = PasswordField('Senha', validators=[Required()])
	remember_me = BooleanField('Lembrar minha senha')
	submit = SubmitField('Entrar')