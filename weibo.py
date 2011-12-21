#!/usr/bin/env python
# coding: utf-8

import logging
import urllib
import mimetools
import itertools

from tornado import escape
from tornado.httputil import url_concat
from tornado.auth import httpclient, OAuth2Mixin

class WeiboMixin(OAuth2Mixin):
    """Weibo authentication using OAuth2."""
    _OAUTH_ACCESS_TOKEN_URL = "https://api.weibo.com/oauth2/access_token"
    _OAUTH_AUTHORIZE_URL = "https://api.weibo.com/oauth2/authorize"
    _OAUTH_NO_CALLBACKS = False

    def get_authenticated_user(self, redirect_uri, client_id, client_secret,
                               code, callback, extra_fields=None):
        """Handles the login for the Weibo user, returning a user object.

           Example usage::

          class WeiboLoginHandler(LoginHandler, WeiboMixin):
              @tornado.web.asynchronous
              def get(self):
                  if self.get_argument("code", False):
                      self.get_authenticated_user(
                          redirect_uri='/auth/weibo/',
                          client_id=self.settings["weibo_client_id"],
                          client_secret=self.settings["weibo_client_secret"],
                          code=self.get_argument("code"),
                          callback=self.async_callback(self._on_login))
                      return
                  self.authorize_redirect(redirect_uri='/auth/weibo/',
                                        client_id=self.settings["weibo_client_id"],
                                        extra_params={"response_type": "code"})
              def _on_login(self, user):
                  logging.error(user)
                  self.finish()

        """
        http = httpclient.AsyncHTTPClient()
        args = {
            "redirect_uri": redirect_uri,
            "code": code,
            "client_id": client_id,
            "client_secret": client_secret,
            "extra_params": {"grant_type": "authorization_code"},
            }
        post_args = args.copy()
        post_args.update({"grant_type": "authorization_code"})

        fields = set(['uid'])
        if extra_fields: fields.update(extra_fields)

        http.fetch(
            self._oauth_request_token_url(**args),
            method="POST",
            body=urllib.urlencode(post_args),
            callback=self.async_callback(self._on_access_token, redirect_uri,
                client_id, client_secret, callback, fields))

    def _on_access_token(self, redirect_uri, client_id, client_secret,
                         callback, fields, response):
        if response.error:
            logging.warning('Weibo auth error: %s' % str(response))
            callback(None)
            return

        json = escape.json_decode(response.body)
        session = {
            "access_token": json["access_token"],
            "expires": json.get("expires_in")
        }

        self.weibo_request(
            path="/account/get_uid.json",
            callback=self.async_callback(
                self._on_get_user_id, callback, session, fields),
            access_token=session["access_token"],
        )


    def _on_get_user_id(self, callback, session, fields, user):
        if user is None:
            callback(None)
            return

        fields = ["id", "screen_name", "profile_image_url"]
        uid = user["uid"]
        self.weibo_request(
            path="/users/show.json",
            callback=self.async_callback(
                self._on_get_user_info, callback, session, fields),
            access_token=session["access_token"],
            uid=uid
        )

    def _on_get_user_info(self, callback, session, fields, user):
        if user is None:
            callback(None)
            return

        fieldmap = {}
        for field in fields:
            fieldmap[field] = user.get(field)

        fieldmap.update({"access_token": session["access_token"], "session_expires": session.get("expires_in")})
        callback(fieldmap)


    def weibo_request(self, path, callback, access_token=None,
                      post_args=None, **args):
        """Fetches the given relative API path

        If the request is a POST, post_args should be provided. Query
        string arguments should be given as keyword arguments.

        Many methods require an OAuth access token which you can obtain
        through authorize_redirect() and get_authenticated_user(). The
        user returned through that process includes an 'access_token'
        attribute that can be used to make authenticated requests via
        this method. Example usage::

            class MainHandler(tornado.web.RequestHandler,
                              WeiboMixin):
                @tornado.web.authenticated
                @tornado.web.asynchronous
                def get(self):
                    self.weibo_request(
                        "/statuses/update.json",
                        post_args={"status": "I am posting from my Tornado application!"},
                        access_token=self.current_user["access_token"],
                        callback=self.async_callback(self._on_post))

                def _on_post(self, new_entry):
                    if not new_entry:
                        # Call failed; perhaps missing permission?
                        self.authorize_redirect()
                        return
                    self.finish("Posted a message!")


        To send a request to ``/statuses/upload``, the ``pic`` parameter is
        required and it should be a dict with ``filename``, ``content`` and
        ``mime_type`` set. Example usage::

            class UploadHandler(tornado.web.RequestHandler, WeiboMixin):
                @tornado.web.authenticated
                @tornado.web.asynchronous
                @tornado.gen.engine
                def get(self):
                    # ...
                    f = open('foo.png', 'r') # open the image file
                    pic = {
                        'filename': 'foo.png', # must present, but the value does not matter
                        'content': f.read(),
                        'mime_type': 'image/png'
                    }
                    f.close()
                    result = yield tornado.gen.Task(self.weibo_request, '/statuses/upload.json',
                        access_token=self.current_user["access_token"],
                        status='I like this photo!',
                        pic=pic
                    )
                    # do something with the result ...
        """
        url = "https://api.weibo.com/2" + path
        if path == "/statuses/upload.json":
            # this request should be handled differently
            return self._weibo_upload_request(url, callback,
                access_token, args.get("pic"), status=args.get("status"))
        all_args = {}
        if access_token:
            all_args["access_token"] = access_token
            all_args.update(args)
            all_args.update(post_args or {})
        if all_args: url += "?" + urllib.urlencode(all_args)
        callback = self.async_callback(self._on_weibo_request, callback)
        http = httpclient.AsyncHTTPClient()
        if post_args is not None:
            http.fetch(url, method="POST", body=urllib.urlencode(post_args),
                callback=callback)
        else:
            http.fetch(url, callback=callback)

    def _on_weibo_request(self, callback, response):
        if response.error:
            logging.warning("Error response %s fetching %s", response.error,
                response.request.url)
            callback(None)
            return
        callback(escape.json_decode(response.body))


    def _weibo_upload_request(self, url, callback,
                              access_token, pic, status=None):
        # build and send the multipart/form-data request
        if pic is None:
            raise Exception("pic is required!")
        form = MultiPartForm()
        form.add_file("pic", pic["filename"], pic["content"], pic["mime_type"])
        form.add_field("status", status)
        headers = {
            "Content-Type": form.get_content_type()
        }
        args = {
            "access_token": access_token
        }
        url += "?" + urllib.urlencode(args)
        http = httpclient.AsyncHTTPClient()
        http.fetch(url, method="POST", body=str(form),
            callback=self.async_callback(self._on_weibo_request, callback),
            headers=headers)


class MultiPartForm(object):
    """Helper class to build a multipart form

    Copied from http://www.doughellmann.com/PyMOTW/urllib2/
    """

    def __init__(self):
        self.form_fields = []
        self.files = []
        self.boundary = mimetools.choose_boundary()
        return

    def get_content_type(self):
        return 'multipart/form-data; boundary=%s' % self.boundary

    def add_field(self, name, value):
        """Add a simple field to the form data."""
        self.form_fields.append((name, value))
        return

    def add_file(self, fieldname, filename, body, mimetype):
        """Add a file to be uploaded."""
        self.files.append((fieldname, filename, mimetype, body))
        return

    def __str__(self):
        """Return a string representing the form data,
        including attached files.
        """
        # Build a list of lists, each containing "lines" of the
        # request.  Each part is separated by a boundary string.
        # Once the list is built, return a string where each
        # line is separated by '\r\n'.
        parts = []
        part_boundary = '--' + self.boundary

        # Add the form fields
        parts.extend(
            [part_boundary,
             'Content-Disposition: form-data; name="%s"' % name,
             '',
             value,
             ]
            for name, value in self.form_fields
        )

        # Add the files to upload
        parts.extend(
            [part_boundary,
             'Content-Disposition: form-data; name="%s"; filename="%s"' %\
             (field_name, filename),
             'Content-Type: %s' % content_type,
             '',
             body,
             ]
            for field_name, filename, content_type, body in self.files
        )

        # Flatten the list and add closing boundary marker,
        # then return CR+LF separated data
        flattened = list(itertools.chain(*parts))
        flattened.append('--' + self.boundary + '--')
        flattened.append('')
        return '\r\n'.join(flattened)