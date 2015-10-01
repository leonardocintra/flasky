from flask.ext.wtf import Form
from wtforms import StringField, SubmitField, TextAreaField, BooleanField, SelectField
from wtforms import ValidationError
from wtforms.validators import Required, Length, Email, Regexp
from ..models import Role, User

class NameForm(Form):
	name = StringField('Qual é o seu nome?', validators=[Required()])
	submit = SubmitField('Enviar')


class EditProfileForm(Form):
	name = StringField('Nome', validators=[Length(0, 64)])
	location = StringField('Localização', validators=[Length(0,64)])
	about_me = TextAreaField('Sobre mim')
	submit = SubmitField('Salvar')


class EditProfileAdminForm(Form):
	email = StringField('Email', validators=[Required(), Length(1,64), Email()])
	username = StringField('Usuario', validators=[Required(), Length(1,64),
							Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0, 'Nome de usuário não pode ter caracteres epeciais')])
	confirmed = BooleanField('Confirmado')
	role = SelectField('Perfil', coerce=int)
	name = StringField('Nome', validators=[Length(0, 64)])
	location = StringField('Localização', validators=[Length(0, 64)])
	about_me = TextAreaField('Sobre mim')
	submit = SubmitField('Salvar')

	def __init__(self, user, *args, **kwargs):
		super(EditProfileAdminForm, self).__init__(*args, **kwargs)
		self.role.choices = [(role.id, role.name) for role in Role.query.order_by(Role.name).all()]
		self.user = user

	def validate_email(self, field):
		if field.data != self.user.email and User.query.filter_by(email=field.data).first():
			raise ValidationError('Esse email ja esta registrado')

	def validade_username(self, field):
		if field.data != self.user.username and User.query.filter_by(username=field.data).first():
			raise ValidationError('Esse usuario ja esta em uso')
