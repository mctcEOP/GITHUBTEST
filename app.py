from flask import FLask, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

# Adding Necessities
app = Flask(__name__)
app.secret_key = 'your_secret_key'

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)

@route('/')
def home()
    return render_template('home.html')

if __name__ == '__main__':
    app.run(debug=True)