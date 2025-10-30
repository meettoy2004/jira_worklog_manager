from flask_wtf import FlaskForm
from wtforms import StringField, BooleanField, SubmitField
from wtforms.validators import DataRequired, Length, URL

class JiraInstanceForm(FlaskForm):
    alias = StringField('Instance Name (e.g., Jira 1 - Work Projects)',
                       validators=[DataRequired(), Length(min=2, max=100)])
    base_url = StringField('Jira URL',
                          validators=[DataRequired(), URL(message='Please enter a valid URL')])
    jira_username = StringField('Your Jira Email',
                               validators=[DataRequired()])
    api_token = StringField('Jira API Token', 
                           validators=[DataRequired(), Length(min=10, message='API token must be at least 10 characters')])
    is_active = BooleanField('Active', default=True)
    submit = SubmitField('Save Jira Instance')