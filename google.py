from flask import Flask, redirect, url_for, session, render_template, g, flash
from flask_oauth import OAuth
import requests
import json

# get some cool stuff for decorators
from functools import wraps
import MySQLdb as mdb

# database config
DB_HOST = 'localhost'
DB_USER = 'root'
DB_PASS = 'db_user'
DB_NAME = 'db_pass'



# You must configure these 3 values from Google APIs console
# https://code.google.com/apis/console
GOOGLE_CLIENT_ID = ''
GOOGLE_CLIENT_SECRET = ''
REDIRECT_URI = '/authorized'  # one of the Redirect URIs from Google APIs console
USERINFO_URL = 'https://www.googleapis.com/oauth2/v1/userinfo'

ALLOWED_HD = 'domian.com'   # your domain here

SECRET_KEY = 'development key'
DEBUG = True

app = Flask(__name__)
app.debug = DEBUG
app.secret_key = SECRET_KEY
oauth = OAuth()

google = oauth.remote_app('google',
                          base_url='https://www.google.com/accounts/',
                          authorize_url='https://accounts.google.com/o/oauth2/auth',
                          request_token_url=None,
                          request_token_params={'scope': 'https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile',
                                                'response_type': 'code'},   #, 'hd': 'domain.com'},  # set HD to control the domain used
                          access_token_url='https://accounts.google.com/o/oauth2/token',
                          access_token_method='POST',
                          access_token_params={'grant_type': 'authorization_code'},
                          consumer_key=GOOGLE_CLIENT_ID,
                          consumer_secret=GOOGLE_CLIENT_SECRET)


def check_login(f):
  @wraps(f)
  def decorated_function(*args, **kwargs):
    if session.get('access_token') is None:
      return redirect(url_for('login'))
    return f(*args, **kwargs)
  return decorated_function


@app.route('/')
#@check_login
def index():

  g.db_cur.execute("select * from users where id = %(user_id)s;", {'user_id' : session.get('user_id') } )
  cur_user = g.db_cur.fetchone()
  print "Session id: %s" % session.get('user_id')

  return render_template('index.html', cur_user=cur_user)

@app.route('/protected')
@check_login
def protected():
  g.db_cur.execute("select * from users where id = %(user_id)s;", {'user_id' : session.get('user_id') } )
  cur_user = g.db_cur.fetchone()

  return render_template('index.html', cur_user=cur_user)



@app.route('/login')
def login():

  callback=url_for('authorized', _external=True)
  return google.authorize(callback=callback)

@app.route('/logout')
def logout():

  session.pop('access_token', None)
  session.pop('user_id', None)
  session.pop('name', None)
  return redirect(url_for('index'))



@app.route(REDIRECT_URI)
@google.authorized_handler
def authorized(resp):
  # callback handler for oauth
  # user has logged in via OAuth and the http request to get userinfo has
  # returned sucessfully
    
  # grab the access token google sent back
  access_token = None
  access_token = resp['access_token']

  if access_token is not None:

    # now use that token to get user info from the api
    headers = {'Authorization': 'OAuth %s' % access_token}

    r = requests.get("https://www.googleapis.com/oauth2/v1/userinfo", headers=headers)

    if r.status_code != 200:
      print "REQUEST FAILED!"
      return redirect(url_for('logout'))
    else:

      # load the user info from the json response
      userinfo = json.loads(r.content)

      # check the HD variable from the reponse to see if the user is logging in
      # using the correct domain
      if userinfo['hd'] != ALLOWED_HD:
        flash("That domain is not allowed")
        return redirect(url_for('index'))

      # check to see if we have a token on file for this user already
      # and update the database with the new token if needed
      g.db_cur.execute("select * from users where email = %(email)s;", { "email": userinfo['email'] })
      check_user = g.db_cur.fetchone()

      if check_user is not None:
        # we already have this user in the database

        # load the user info from the json response
        userinfo = json.loads(r.content)
        # set required vars in the session obj
        session['user_id'] = check_user['id']
        session['access_token'] = access_token
        session['name'] = check_user['name']

        # update database with new access token
        g.db_cur.execute("update users set access_token = %(access_token)s where email = %(email)s;", { "access_token": access_token, "email": check_user['email'] })
        g.db_con.commit()
        # redirect back to main page
        return redirect(url_for('index'))

      else:
        # new user logging in for the first time

        # stick new user into the database
        g.db_cur.execute("insert into users(name, email, pictureurl, hd, access_token) values(%(name)s, %(email)s, %(pictureurl)s, %(hd)s, %(access_token)s);", \
            { 'name': userinfo['name'], 'email': userinfo['email'], 'pictureurl': userinfo['picture'], 'hd': userinfo['hd'], 'access_token': access_token })
        
        # set required vars in the session object
        session['access_token'] = access_token
        session['user_id'] = g.db_con.insert_id()
        session['name'] = userinfo['name']

        g.db_con.commit()

        return redirect(url_for('index'))


@google.tokengetter
def get_access_token():
    return session.get('access_token')


## DATABASE SETUP
def connect_db():
  return mdb.connect(DB_HOST, DB_USER, DB_PASS, DB_NAME)

@app.before_request
def before_req():

  g.db_con = connect_db()
  g.db_cur = g.db_con.cursor(mdb.cursors.DictCursor)
  #g.db = connect_db()

@app.teardown_request
def teardown_req(exception):
  db = getattr(g, 'db', None)
  if db is not None:
    db_cur.close()

def main():
    app.run()


if __name__ == '__main__':
    main()
