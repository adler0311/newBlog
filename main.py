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

from google.appengine.ext import ndb

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
								autoescape=True)


def write(*a, **kw):
	self.response.out.write(*a, **kw)

def render_str(template, **params):
	t=jinja_env.get_template(template)
	return t.render(params)

def render(template, **kw):
	self.write(render_str(template, **kw))


class BlogHandler(webapp2.RequestHandler):
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

	def render_str(self, template, **params):
		t=jinja_env.get_template(template)
		return t.render(params)

	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))


class Post(ndb.Model):
	subject=ndb.StringProperty(required=True)
	content=ndb.TextProperty(required=True)
	created=ndb.DateTimeProperty(auto_now_add=True)

	def render(self):
		self._render_text=self.content.replace('\n', '<br>')
		return render_str("post.html", p=self)


class MainPage(BlogHandler):
	def get(self):
		posts = Post.query()
		posts = posts.order(-Post.created)
		self.render('front.html', posts=posts)


class newPost(BlogHandler):
	def get(self):
		self.render('newpost.html')

	def post(self):
		subject=self.request.get('subject')
		content=self.request.get('content')
		have_error = False

		if subject and content:
			p = Post(subject=subject,
					 content=content)
			p.put()

			self.redirect('/postpage/%s' % str(p.key.id()))

		else:
			msg="제목과 내용을 둘 다 입력해주세요."
			self.render('newpost.html', subject=subject, content=content, msg=msg)


class postPage(BlogHandler):
	def get(self, post_id):
		key=ndb.Key(Post, int(post_id))
		post = key.get()
		self.render("permalink.html", p=post)


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




app = webapp2.WSGIApplication([
	('/', MainPage),
	('/newpost', newPost),
	('/postpage/([0-9]+)', postPage),
	('/edit/([\d]+)', editPost),
	('/delete/([\d]+)', deletePost),
], debug=True)


