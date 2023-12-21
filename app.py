from flask import Flask, render_template, url_for, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt

import json
from flask_mqtt import Mqtt
from flask_socketio import SocketIO

app = Flask(__name__)
db = SQLAlchemy()
bcrypt = Bcrypt(app)

app = Flask(__name__)
app.config['SECRET'] = '0123'
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.config['MQTT_BROKER_URL'] = 'broker.emqx.io'
app.config['MQTT_BROKER_PORT'] = 1883
app.config['MQTT_USERNAME'] = 'demo'
app.config['MQTT_PASSWORD'] = 'demo'
app.config['MQTT_KEEPALIVE'] = 5
app.config['MQTT_TLS_ENABLED'] = False


mqtt = Mqtt(app)
socketio = SocketIO(app)

mqtt.publish('wearable/device', 'hello, I am from wearable website')

@socketio.on('subscribe')
def handle_subscribe(json_str):
 data = json.loads(json_str)
 mqtt.subscribe(data['topic'])



@mqtt.on_message()
def handle_mqtt_message(client, userdata, message):
 data = dict(
     topic=message.topic,
     payload=message.payload.decode()
 )
 socketio.emit('mqtt_message', data=data)


@mqtt.on_log()
def handle_logging(client, userdata, level, buf):
 print(level, buf)


#app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db' # set the option
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgres://kvtitbbeigjxvy:a1d1fc5ca65f29d7800334efa25c31373f1c4387f818898f668eb801a0316fa4@ec2-52-4-153-146.compute-1.amazonaws.com:5432/d4lo58sj89oect' # set the option
app.config['SECRET_KEY'] = '123'
db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
   return User.query.get(int(user_id))


class User(db.Model, UserMixin):
   id = db.Column(db.Integer, primary_key=True)
   username = db.Column(db.String(20), nullable=False, unique=True)
   password = db.Column(db.String(128), nullable=False)


class RegisterForm(FlaskForm):
   username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
   password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
   submit = SubmitField('Register')


   def validate_username(self, username):
       existing_user_username = User.query.filter_by(
           username=username.data).first()
       if existing_user_username:
           raise ValidationError(
               'That username already exists. Please choose a different one.')


class LoginForm(FlaskForm):
   username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
   password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
   submit = SubmitField('Login')


@app.route('/')
def home():
   return render_template('home.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
   form = LoginForm()
   if form.validate_on_submit():
       user = User.query.filter_by(username=form.username.data).first()
       if user:
           if bcrypt.check_password_hash(user.password, form.password.data):
               login_user(user)
               return redirect(url_for('dashboard'))
   return render_template('login.html', form=form)


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
   return render_template('dashboard.html')


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
   logout_user()
   return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
   form = RegisterForm()


   if form.validate_on_submit():
       hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
       new_user = User(username=form.username.data, password=hashed_password)
       db.session.add(new_user)
       db.session.commit()
       return redirect(url_for('login'))


   return render_template('register.html', form=form)


with app.app_context():
   db.create_all()


if __name__ == "__main__":
   app.run(debug=True)
   socketio.run(app, host='0.0.0.0', port=5000, use_reloader=False, debug=True)