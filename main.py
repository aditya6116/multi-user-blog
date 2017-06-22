import webapp2
import jinja2
import re
import os
import hashlib
import hmac
import random
import string
from string import letters
from google.appengine.ext import db
secret = "adsfadfadsfasfafsa"


template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
password_re = re.compile(r"^.{3,20}$")
email_re = re.compile(r"^[\S]+@[\S]+.[\S]+$")


def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(5))


def make_pw_hash(name, pw):
    salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (h, salt)


def valid_pw(name, pw, h):
    salt = h.split(",")[1]
    if h.split(",")[0] == hashlib.sha256(name + pw + salt).hexdigest():
        return True
    else:
        return False


def check_pw_hash(username, password, db_password):
    salt = db_password.split(",")[1]
    pw = hashlib.sha256(username + password + salt).hexdigest()
    if db_password.split(",")[0] == pw:
        return True
    else:
        return False


def hash_str(s):
    return hmac.new(secret, s).hexdigest()


def make_secure_val(s):
    return "%s|%s" % (s, hash_str(s))


def check_secure_val(h):
    val = h.split('|')[0]
    if h == make_secure_val(val):
        return val


def valid_username(username):
    return USER_RE.match(str(username))


def check_username(username):
    db_username = db.GqlQuery(
        "select * from User_database where username = :username", username=username)
    name = db_username.get()
    if name:
        return 1
    else:
        return 0


def valid_password(password):
    return password_re.match(password)


def valid_email(email):
    return email_re.match(email)


def login(username, password):
    db_username = db.GqlQuery(
        "select * from User_database where username =:username", username=username)
    name = db_username.get()
    if name:
        if check_pw_hash(username, password, name.password):
            return True
        else:
            return False
    else:
        return False

class Blog_database(db.Model):
    title = db.StringProperty(required=True)
    post = db.TextProperty(required=True)
    poster_name = db.StringProperty(required=True)
    likes = db.IntegerProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    

class User_database(db.Model):
    username = db.StringProperty(required=True)
    password = db.StringProperty(required=True)
    email = db.StringProperty(required=True)



class Comment_database(db.Model):
    poster_id = db.IntegerProperty(required=True)
    poster_name = db.StringProperty(required=True)
    comment = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)

class Like_database(db.Model):
    poster_id = db.IntegerProperty(required=True)
    liker_name = db.StringProperty(required=True)




class MainHandler(webapp2.RequestHandler):

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.response.out.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header('Set-Cookie',
                                         '%s=%s; Path=/'
                                         % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def check_login(self):
        username = self.read_secure_cookie("username")
        if username:
            return True
        else:
            return False


class Welcome(MainHandler):

    def get(self):
        username = self.read_secure_cookie('username')
        if username:
            self.render('welcome.html', username=username)
        else:
            self.redirect('/blog/signup')


class Signup(MainHandler):

    def get(self):
        self.render("Signup.html")

    def post(self):
        have_fault = False
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')
        params = dict(username=username,
                      email=email)

        if not valid_username(username):
            params['error_username'] = "Please enter a valid username"
            have_fault = True

        distinct_username = check_username(username)
        if distinct_username == 1:
            distinct_username = 0
            params['error_username'] = "This username already exists!"
            have_fault = True

        if not valid_password(password):
            params['error_password'] = "The password is invalid"
            have_fault = True
        elif password != verify:
            params['error_verify'] = "Your passwords didn't match."
            have_fault = True

        if not valid_email(email):
            params['error_email'] = "Please enter a valid e-mail"
            have_fault = True

        if have_fault:
            self.render('signup.html', **params)
        else:
            username = str(username)
            password = str(make_pw_hash(username, password))
            commit = User_database(username=username, password=password, email=email)
            commit.put()
            username = self.set_secure_cookie("username", username)
            self.redirect('/blog/welcome')



class Mainpage_Handler(MainHandler):

    def get(self):

        posts = db.GqlQuery("select * from Blog_database order by created desc")
        comment = db.GqlQuery("select * from Comment_database order by created asc")
        if self.check_login():
            login = "logout"
            signup = ""
        else:
            login = "login"
            signup = "signup"
        self.render("frontpage.html", posts=posts, login=login,
                    comment=comment, signup=signup)


class Login_Handler(MainHandler):

    def get(self):
        self.render("login.html")

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        if login(username, password):
            self.set_secure_cookie("username", str(username))
            self.redirect('/blog/welcome')
        else:
            self.render("login.html", error="login is not valid")



class Logout_Handler(MainHandler):

    def get(self):
        self.response.headers.add_header('Set-Cookie',
                                         'username =; Path=/')
        self.render("logout.html")
        self.redirect("/blog/login")


class Newpost_handler(MainHandler):

    def render_front(self, title="", post="", error=""):
        self.render("formpage.html", title=title, post=post, error=error)

    def get(self):
        if self.check_login():
            self.render_front()
        else:
            self.redirect("/blog/login")

    def post(self):
        if self.check_login():
            title = self.request.get("title")
            post = self.request.get("post")
            poster_name = self.request.cookies.get("username")
            username = poster_name.split('|')[0]
            if title and post:
                post = post.replace('\n', '<br>')
                b = 0
                commit = Blog_database(title=title, post=post, poster_name=username, likes=b)
                commit.put()
                a_id = commit.key().id()
                self.redirect('/blog/'+str(a_id))
            else:
                self.render_front(
                    title=title, post=post, error="The details are invalid")
        else:
            self.redirect("/blog/login")


class Like_Handler(MainHandler):

    def get(self, poster_id):
        a = int(poster_id)
        key = db.Key.from_path('Blog_database', int(poster_id), parent=None)
        post = db.get(key)
        if not post:
            return self.redirect('login')
        current_user = self.read_secure_cookie("username")
        if current_user:
            if post.poster_name == current_user:
                self.render("likepage.html", error="cannot like your own post")
            else:
                all_likes = db.GqlQuery(
                    "select * from Like_database where poster_id =:poster_id",
                     poster_id=int(poster_id))
                flag = 0
                if post.likes != 0:
                    likes = all_likes.get()
                    if likes.liker_name == current_user:
                        flag == 1
                        self.render("likepage.html", error="cannot like twice")
                    else:
                        a = Like_database(
                            poster_id=int(poster_id), liker_name=current_user)
                        a.put()
                        post.likes += 1
                        post.put()
                        self.redirect("/blog")
                else:
                    commit = Like_database(poster_id=int(poster_id), liker_name=current_user)
                    commit.put()
                    post.likes += 1
                    post.put()
                    self.redirect("/blog")
        else:
            self.render("Signup.html")



class Comment_Handler(MainHandler):

    def post(self, poster_id):
        current_user = self.read_secure_cookie("username")
        if current_user:
            comment = self.request.get('comment_textarea')
            if comment:
                commit = Comment_database(
                    poster_id=int(poster_id),
                    poster_name=current_user,
                    comment=comment)
                commit.put()
                self.redirect("/blog")
        else:
            self.redirect("/blog/login")



class Comment_edit_Handler(MainHandler):

    def get(self, comment_id):
        current_user = self.read_secure_cookie("username")
        if current_user:
            a = int(comment_id)
            key = db.Key.from_path('Comment_database', int(comment_id), parent=None)
            comment = db.get(key)
            if comment:
                if comment.poster_name == self.read_secure_cookie("username"):
                    self.render("comment_edit.html", a=comment)
                else:
                    self.render(
                        "likepage.html",
                         error="One person can edit only one post")
        else:
            self.redirect("/blog/login")

    def post(self, comment_id):
        current_user = self.read_secure_cookie("username")
        if current_user:
            comment_get = self.request.get('comment_edit')
            a = int(comment_id)
            key = db.Key.from_path('Comment_database', int(comment_id), parent=None)
            comment_data = db.get(key)
            if comment_data:
                if comment_data.poster_name == self.read_secure_cookie("username"):
                    comment_data.comment = comment_get
                    comment_data.put()
                    self.redirect("/blog")
        else:
            self.redirect("/blog/login")


class Comment_delete_Handler(MainHandler):

    def get(self, comment_id):
        current_user = self.read_secure_cookie("username")
        if current_user:
            a = int(comment_id)
            key = db.Key.from_path('Comment_database', int(comment_id), parent=None)
            comment = db.get(key)
            if comment:
                if comment.poster_name == self.read_secure_cookie("username"):
                    comment.delete()
                    self.render("likepage.html", error="comment deleted")
                    self.redirect("/blog")
                else:
                    self.render(
                        "likepage.html",
                         error="One person can edit only one post")
        else:
            self.redirect("/blog/login")

class Post_edit_Handler(MainHandler):
    def get(self, poster_id):
        current_user = self.read_secure_cookie("username")
        if current_user:
            a = int(poster_id)
            key = db.Key.from_path('Blog_database',int(poster_id),
                parent=None)
            post = db.get(key)
            if post:
                if post.poster_name == self.read_secure_cookie("username"):
                    self.render("edit_post.html",
                    login="logout", a=post)
                else:
                    self.render(
                        "likepage.html",
                        error="One user can edit only one post")
        else:
            self.redirect("/blog/login")

    def post(self, poster_id):
        current_user = self.read_secure_cookie("username")
        if current_user:
            edited_post = self.request.get('comment_edit')
            a = int(poster_id)
            key = db.Key.from_path('Blog_database', int(poster_id), parent=None)
            post_data = db.get(key)
            if post_data:
                if post_data.poster_name == self.read_secure_cookie("username"):
                    post_data.post = edited_post
                    post_data.put()
                    self.redirect("/blog")
        else:
            self.redirect("/blog/login")



class Post_delete_Handler(MainHandler):

    def get(self, poster_id):
        current_user = self.read_secure_cookie("username")
        if current_user:
            a = int(poster_id)
            key = db.Key.from_path('Blog_database', int(poster_id), parent=None)
            post_data = db.get(key)
            if post_data:
                if post_data.poster_name == self.read_secure_cookie("username"):
                    post_data.delete()
                    self.render("likepage.html", error="The post has been deleted")
                    self.redirect("/blog")
                else:
                    self.render(
                        "likepage.html",
                         error="One user can edit only one post")
        else:
            self.redirect("/blog/login")


class Peralink(MainHandler):

    def get(self, a_id):
        a = int(a_id)
        key = db.Key.from_path('Blog_database', int(a_id), parent=None)
        post = db.get(key)
        if not post:
            self.write("error 404")
        else:
            self.render("permalink.html", posts=post)



app = webapp2.WSGIApplication([('/blog', Mainpage_Handler),
                               ('/blog/Newpage', Newpost_handler),
                               ('/blog/([0-9]+)', Peralink),
                               ('/blog/signup', Signup),
                               ('/blog/welcome', Welcome),
                               ('/blog/login', Login_Handler),
                               ('/blog/logout', Logout_Handler),
                               ('/blog/like/([0-9]+)', Like_Handler),
                               ('/blog/comment/([0-9]+)', Comment_Handler),
                               ('/blog/comment_edit/([0-9]+)', Comment_edit_Handler),
                               ('/blog/delete/([0-9]+)', Comment_delete_Handler),
                               ('/blog/Post_edit/([0-9]+)', Post_edit_Handler),
                               ('/blog/Post/([0-9]+)', Post_delete_Handler)
                               ],
                              debug=True)



#If it requires much of changes write me down.
# It is my last day.