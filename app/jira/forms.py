from flask_wtf import FlaskForm
from wtforms import StringField, BooleanField, SubmitField, PasswordField
from wtforms.validators import DataRequired, Length, URL

class JiraInstanceForm(FlaskForm):
    alias = StringField('Instance Name (e.g., Jira 1 - Work Projects)',
                       validators=[DataRequired(), Length(min=2, max=100)])
    base_url = StringField('Jira URL',
                          validators=[DataRequired(), URL(message='Please enter a valid URL')])
    jira_username = StringField('Your Jira Username/Email',
                               validators=[DataRequired()])
    jira_password = PasswordField('Your Jira Password',
                                 validators=[DataRequired(), Length(min=1, message='Password is required')])
    is_active = BooleanField('Active', default=True)
    submit = SubmitField('Save Jira Instance')