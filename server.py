from flask import Flask, render_template, send_from_directory, Response, request, flash, redirect
# from flask_socketio import SocketIO
from pathlib import Path
from capture import capture_and_save
from camera import Camera
import argparse, logging, logging.config, conf
from flask_login import LoginManager, login_user, login_required, current_user, logout_user
import os
from flask_sqlalchemy import SQLAlchemy
from helper import check_passwords, encrypt

logging.config.dictConfig(conf.dictConfig)
logger = logging.getLogger(__name__)

camera = Camera()
camera.run()

app = Flask(__name__)
# app.config["SECRET_KEY"] = "secret!"
# socketio = SocketIO(app)

db = SQLAlchemy()
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SECRET_KEY'] = os.urandom(32)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'data.sqlite')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

from models import User

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.after_request
def add_header(r):
	"""
	Add headers to both force latest IE rendering or Chrome Frame,
	and also to cache the rendered page for 10 minutes
	"""
	r.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
	r.headers["Pragma"] = "no-cache"
	r.headers["Expires"] = "0"
	r.headers["Cache-Control"] = "public, max-age=0"
	return r


@app.route("/camera")
@login_required
def entrypoint():
	logger.debug("Requested /camera")
	return render_template("index.html")


@app.route("/")
def start():
	logger.debug("Requested /")
	return render_template("start.html")


@app.route("/r")
def capture():
	logger.debug("Requested capture")
	im = camera.get_frame(_bytes=False)
	capture_and_save(im)
	return render_template("send_to_init.html")


@app.route("/images/last")
def last_image():
	logger.debug("Requested last image")
	p = Path("images/last.png")
	if p.exists():
		r = "last.png"
	else:
		logger.debug("No last image")
		r = "not_found.jpeg"
	return send_from_directory("images",r)


def gen(camera):
	logger.debug("Starting stream")
	while True:
		frame = camera.get_frame()
		yield (b'--frame\r\n'
			   b'Content-Type: image/png\r\n\r\n' + frame + b'\r\n')


@app.route("/stream")
@login_required
def stream_page():
	logger.debug("Requested stream page")
	return render_template("stream.html")


@app.route("/video_feed")
def video_feed():
	return Response(gen(camera),
		mimetype="multipart/x-mixed-replace; boundary=frame")


@app.route('/send-client', methods=['POST'])
def send_client():
	return 'Здесь будет отправка данных нам на info почту'


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
	if request.method == 'GET':
		return render_template('profile.html', user=current_user)


@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
	if request.method == 'GET':
		return render_template('settings.html')
	else:
		username = request.form.get('username')
		fio = request.form.get('fio')
		current_user.username = username
		current_user.name = fio
		db.session.commit()
		return redirect('/profile')


@app.route('/login', methods=['GET', 'POST'])
def login():
	if request.method =='GET':
		return render_template('login.html')
	else:
		email = request.form.get('email')
		password = request.form.get('password')
		remember = True if request.form.get('remember') else False

		user = User.query.filter_by(email=email).first()

		# check if the user actually exists
		# take the user-supplied password, hash it, and compare it to the hashed password in the database
		if not user or not check_passwords(password, user.password):
			user.authenticated = False
			flash('Please check your login details and try again.')
			return redirect('/login')  # if the user doesn't exist or password is wrong, reload the page

		print(login_user(user, remember=remember))
		user.authenticated = True
		# if the above check passes, then we know the user has the right credentials
		return redirect('/profile')


@app.route('/register', methods=['GET', 'POST'])
def register():
	if request.method == 'GET':
		return render_template('register.html')
	else:
		username = request.form.get('username')
		email = request.form.get('email')
		password = request.form.get('password')
		repeat = request.form.get('repeat')

		user = User.query.filter_by(email=email).first()

		if user:
			flash('Пользователь с такой почтой уже существует')
			return redirect('/register')

		if password != repeat:
			flash('Введенные пароли не совпадают')
			return redirect('/register')

		new_user = User(email=email, username=username, password=encrypt(password))
		db.session.add(new_user)
		db.session.commit()

		return redirect('/login')


@app.route('/logout')
@login_required
def logout():
	logout_user()
	return redirect('/')


if __name__=="__main__":
	# socketio.run(app,host="0.0.0.0",port="3005",threaded=True)
	parser = argparse.ArgumentParser()
	parser.add_argument('-p','--port',type=int,default=5000, help="Running port")
	parser.add_argument("-H","--host",type=str,default='0.0.0.0', help="Address to broadcast")
	args = parser.parse_args()
	logger.debug("Starting server")
	app.run(host=args.host,port=args.port)
