from flask.ext.wtf import Form
from wtforms import StringField, SubmitField
from wtforms.validators import Required

class NameForm(Form):
	name = StringField('Qual é o seu nome?', validators=[Required()])
	submit = SubmitField('Enviar')