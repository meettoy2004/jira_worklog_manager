from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, DateField, SubmitField
from wtforms.validators import DataRequired, Length
from datetime import date

class WorklogForm(FlaskForm):
    date = DateField('Date', validators=[DataRequired()], default=date.today)
    time_spent = StringField('Time Spent', validators=[DataRequired()],
                           description='e.g., 1h 30m, 45m, 2h')
    comment = TextAreaField('Comment', validators=[DataRequired(), Length(max=1000)])
    submit = SubmitField('Log Work')