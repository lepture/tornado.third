#!/usr/bin/env python

import logging
import urllib
from tornado import httpclient
from tornado import gen
from tornado.escape import json_decode
from tornado.httputil import url_concat


class RenrenGraphMixin(object):
    _OAUTH_AUTHORIZE_URL = "https://graph.renren.com/oauth/authorize"
    _OAUTH_ACCESS_TOKEN_URL = "https://graph.renren.com/oauth/token"

    _API_URL = 'http://api.renren.com/restserver.do'

    
    def renren_request(self, path, args):
        #TODO
        pass

    @gen.engine
    def get_authenticated_user(self, redirect_uri, callback, scope=None, **args):
        """
        class RenrenHandler(tornado.web.RequestHandler, RenrenGraphMixin):
            @tornado.web.asynchronous
            @gen.engine
            def get(self):
                self.get_authenticated_user(
                    callback=(yield gen.Callback('key')),
                    redirect_uri=url)
                user = yield gen.Wait('key')
                if not user:
                    raise web.HTTPError(500, "Renren auth failed")
                # do something else
                self.finish()
        """

        code = self.get_argument('code', None)
        if not code:
            self.authorize_redirect(redirect_uri, scope=scope, **args)
            return
        self.get_access_token(
            code, callback=(yield gen.Callback('_RenrenMixin.get_authenticated_user')),
            redirect_uri=redirect_uri)

        response = yield gen.Wait('_RenrenMixin.get_authenticated_user')

        if response.error and not response.body:
            logging.warning("Error response %s fetching %s", response.error,
                    response.request.url)
            callback(None)
            return

        try:
            user = json_decode(response.body)
        except:
            logging.warning("Error response %s fetching %s", response.body,
                    response.request.url)
            return
        if 'error' in user:
            logging.warning("Error response %s fetching %s", user['error_description'],
                    response.request.url)
            callback(None)
            return
        callback(user)
        return


    def authorize_redirect(self, redirect_uri, response_type='code', scope=None, **args):
        consumer_token = self._oauth_consumer_token()
        all_args = {
            'client_id': consumer_token['client_id'],
            'redirect_uri': redirect_uri,
            'response_type': response_type,
        }
        if scope: all_args.update({'scope': scope})
        args.update(all_args)
        self.redirect(url_concat(self._OAUTH_AUTHORIZE_URL, args))


    @gen.engine
    def get_access_token(self, code, callback, grant_type='code', redirect_uri=None):
        if grant_type == 'refresh_token':
            args = {
                'grant_type': 'refresh_token',
                'refresh_token': code,
            }
        elif redirect_uri:
            args = {
                'grant_type': 'authorization_code',
                'code': code,
                'redirect_uri': redirect_uri,
            }
        else:
            logging.error('Renren Get Access Token Error. redirect_uri required')
            return
        args.update(self._oauth_consumer_token())

        http = httpclient.AsyncHTTPClient()
        http.fetch(url_concat(self._OAUTH_ACCESS_TOKEN_URL, args),
                   callback=(yield gen.Callback('_RenrenMixin.get_access_token')))
        response = yield gen.Wait('_RenrenMixin.get_access_token')
        callback(response)
        return

    def _oauth_consumer_token(self):
        self.require_setting("renren_client_id", "Renren Client ID")
        self.require_setting("renren_client_secret", "Renren Client Secret")
        token = dict(client_id=self.settings["renren_client_id"],
                     client_secret=self.settings["renren_client_secret"])
        return token

