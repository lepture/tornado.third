#!/usr/bin/env python
# coding: utf-8

import logging
import urllib

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

        """
        url = "https://api.weibo.com/2" + path
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

