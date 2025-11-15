from flask_wtf import FlaskForm
from wtforms import SelectField, SubmitField
from wtforms.validators import DataRequired


class InviteMemberForm(FlaskForm):
    member_id = SelectField('Select User', coerce=int, validators=[DataRequired()])
    submit = SubmitField('Send Invite')
