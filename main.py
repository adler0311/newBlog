#-*- coding: utf-8 -*-
import sys
reload(sys)
sys.setdefaultencoding('utf-8')

# Copyright 2016 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import jinja2
import webapp2
import re
import hmac
from string import letters
import random
import hashlib

from google.appengine.ext import ndb

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
								autoescape=True)


secret = "hrt^$^G$HH$5H454TG2R"

def render_str(template, **params):
	t=jinja_env.get_template(template)
	return t.render(params)

def make_secure_val(val):
	return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
	val = secure_val.split('|')[0]
	if secure_val == make_secure_val(val):
		return val

class BlogHandler(webapp2.RequestHandler):
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

	def render_str(self, template, **params):
		params['user'] = self.user
		return render_str(template, **params)

	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))

	def set_secure_cookie(self,name,val):
		cookie_val = make_secure_val(val)
		self.response.headers.add_header('Set-Cookie', '%s=%s; Path=/' %(name, cookie_val))

	def read_secure_cookie(self, name):
		cookie_val = self.request.cookies.get(name)
		return cookie_val and check_secure_val(cookie_val)

	def login(self, user):
		self.set_secure_cookie('user_id', str(user.key.id()))

	def logout(self):
		self.response.headers.add_header('Set-Cookie', 'user_id=;Path=/')

	def initialize(self, *a, **kw):
		webapp2.RequestHandler.initialize(self, *a, **kw)
		uid = self.read_secure_cookie('user_id')
		self.user = uid and User.by_id(int(uid))


def make_salt(length=5):
	return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt=None):
	if not salt:
		salt = make_salt()
	h = hashlib.sha256(name + pw + salt).hexdigest()
	return '%s,%s' % (salt, h)

def valid_pw_hash(name, pw, h):
	salt = h.split(',')[0]
	return h == make_pw_hash(name, pw, salt)


class User(ndb.Model):
	name = ndb.StringProperty(required=True)
	pw_hash = ndb.StringProperty(required=True)
	email = ndb.StringProperty()
	post = ndb.KeyProperty(kind='Post', repeated=True)


	@classmethod
	def by_name(cls, name):
		u = User.query().filter(User.name==name).get()
		return u

	@classmethod
	def register(cls, username, password, email=None):
		pw_hash = make_pw_hash(username, password)
		return User(name=username, pw_hash=pw_hash, email=email)

	@classmethod
	def by_id(cls, uid):
		return User.get_by_id(uid)

	@classmethod
	def login(cls, name, password):
		u = cls.by_name(name)
		if u and valid_pw_hash(name, password, u.pw_hash):
			return u


class Post(ndb.Model):
	subject=ndb.StringProperty(required=True)
	content=ndb.TextProperty(required=True)
	created=ndb.DateTimeProperty(auto_now_add=True)
	user = ndb.KeyProperty(kind='User')
	comment = ndb.KeyProperty(kind='Comment', repeated=True)

	def render(self):
		self._render_text=self.content.replace('\n', '<br>')
		return render_str("post.html", p=self)


class Comment(ndb.Model):
	name=ndb.StringProperty(required=True)
	pw_hash=ndb.StringProperty(required=True)
	content=ndb.TextProperty(required=True)
	created=ndb.DateTimeProperty(auto_now_add=True)
	post = ndb.KeyProperty(kind='Post')

	@classmethod
	def addComment(cls, name, password, content, post):
		pw_hash = make_pw_hash(name, password)
		return Comment(name=name, pw_hash=pw_hash, content=content, post=post)


class MainPage(BlogHandler):
	def get(self):
		posts = Post.query()
		posts = posts.order(-Post.created)
		#ndb.delete_multi(
    		#User.query().fetch(keys_only=True)
    		#Post.query().fetch(keys_only=True)
    		#Comment.query().fetch(keys_only=True)
		#)

		self.render('front.html', posts=posts)


class newPost(BlogHandler):
	def get(self):
		if self.user:
			self.render('newpost.html')
		else:
			self.redirect('/login')

	def post(self):
		subject=self.request.get('subject')
		content=self.request.get('content')
		have_error = False

		if subject and content:
			p = Post(subject=subject,
					 content=content, user = self.user.key)
			p.put()
			self.user.post.append(p.key)
			self.user.put()

			self.redirect('/postpage/%s' % str(p.key.id()))

		else:
			msg="제목과 내용을 둘 다 입력해주세요."
			self.render('newpost.html', subject=subject, content=content, msg=msg)
	

class postPage(BlogHandler):
	def get(self, post_id):
		key=ndb.Key(Post, int(post_id))
		post = key.get()
		self.render("permalink.html", p=post, comments = post.comment)

	def post(self, post_id):
		key=ndb.Key(Post, int(post_id))
		post = key.get()

		name = self.request.get('name')
		password=self.request.get('password')
		content=self.request.get('content')

		params=dict(name=name,content=content)
		have_error=False		

		if not name:
			params['error_name'] = "이름을 입력하세요"
			have_error=True
		if not password:
			params['error_password'] = "비밀 번호를 입력하세요"
			have_error=True
		if not content:
			params['error_content'] = "내용을 입력하세요"
			have_error=True

		if have_error:
			self.render('permalink.html', p= post, **params)
		else:
			c = Comment.addComment(name, password, content, post.key)
			c.put()
			post.comment.append(c.key)
			post.put()
			self.write(c)
			self.redirect('/postpage/%s' % str(post.key.id()))



class editPost(BlogHandler):
	def get(self, post_id):
		key=ndb.Key(Post, int(post_id))
		post = key.get()
		self.render("editpost.html", post=post)

	def post(self, post_id):
		key=ndb.Key(Post, int(post_id))
		post=key.get()
		
		subject=self.request.get('subject')
		content=self.request.get('content')

		if subject and content:
			post.subject=subject
			post.content=content
			post.put()

			self.redirect('/postpage/%s' % str(post.key.id()))

		else:
			msg="제목과 내용을 둘 다 입력헤주세요."
			self.render('editpost.html', post=post)


class deletePost(BlogHandler):
	def get(self, post_id):
		self.render("deletepost.html")

	def post(self, post_id):
		key=ndb.Key(Post, int(post_id))
		post=key.get()
		post.key.delete()

		self.redirect('/')


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
	return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}")
def valid_password(password):
	return password and PASS_RE.match(password)

EMAIL_RE =re.compile(r"^[\S]+@[\S]+\.[\S]+$")
def valid_email(email):
	return not email or EMAIL_RE.match(email)





class signup(BlogHandler):
	def get(self):
		self.render('signup.html')

	def post(self):
		username=self.request.get('username')
		password=self.request.get('password')
		verify = self.request.get('verify')
		email = self.request.get('email')
		error = False

		params = dict(username=username, email=email)

		if not valid_username(username):
			error=True
			params['error_username'] = "3자~20자 크기의 아이디를 입력하세요."

		if not valid_password(password):
			error=True
			params['error_password'] = "3~20자 크기의 비밀번호를 입력하세요."

		if not valid_email(email):
			error=True
			params['error_email'] = "이메일 형식이 잘못되었습니다."

		if password != verify:
			error=True
			params['error_verify'] = "비밀번호가 다릅니다. 다시 확인해주세요."


		u = User.by_name(username)

		if u:
			error=True
			params['error_username'] = "이미 존재하는 아이디 입니다."

		if error:
			self.render("signup.html", **params)

		else:
			u = User.register(username, password, email)
			u.put()

			self.login(u)
			self.redirect('/')


class login(BlogHandler):
	def get(self):
		self.render('login.html')

	def post(self):
		username = self.request.get('username')
		password = self.request.get('password')

		u = User.login(username, password)
		self.write(u)

		if u:
			self.login(u)
			self.redirect('/')

		else:
			msg="아이디나 비밀번호가 잘못되었습니다."
			self.render('login.html', msg=msg)


class logout(BlogHandler):
	def get(self):
		self.logout()
		self.redirect('/')


class manageComment(BlogHandler):
	def get(self, comment_id):
		key=ndb.Key(Comment, int(comment_id))
		comment = key.get()
		self.render('manageComment.html', c=comment)

	def post(self, comment_id):
		comment_password=self.request.get('comment_password')
		key=ndb.Key(Comment, int(comment_id))
		comment = key.get()
		if valid_pw_hash(comment.name, comment_password, comment.pw_hash):
			self.redirect('/comment/modify/%s' % int(comment_id))
		else:
			msg="패스워드가 일치하지 않습니다."
			self.render('manageComment.html', msg=msg, c=comment)


class modifyComment(BlogHandler):
	def get(self, comment_id):
		key=ndb.Key(Comment, int(comment_id))
		c = key.get()
		self.render('modifyComment.html', c=c)


	def post(self, comment_id):
		key=ndb.Key(Comment, int(comment_id))
		c = key.get()
		post_id = c.post.get().key.id()
		reply = self.request.get('reply')
		c.content = reply
		c.put()

		self.redirect('/postpage/%s' % post_id)


class deleteComment(BlogHandler):
	def get(self, comment_id):
		key=ndb.Key(Comment, int(comment_id))
		c = key.get()
		post_id = c.post.get().key.id()
		c.key.delete()		
		self.redirect('/postpage/%s' % post_id)




app = webapp2.WSGIApplication([
	('/', MainPage),
	('/newpost', newPost),
	('/postpage/([0-9]+)', postPage),
	('/edit/([\d]+)', editPost),
	('/delete/([\d]+)', deletePost),
	('/signup', signup),
	('/login', login),
	('/logout', logout),
	('/comment/manage/([0-9]+)', manageComment),
	('/comment/modify/([0-9]+)', modifyComment),
	('/comment/delete/([0-9]+)', deleteComment)
], debug=True)


