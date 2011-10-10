#!/usr/bin/env python

import logging
import urllib
import hashlib
from tornado import httpclient
from tornado import gen
from tornado.escape import json_decode
from tornado.httputil import url_concat


class RenrenGraphMixin(object):
    _OAUTH_AUTHORIZE_URL = "https://graph.renren.com/oauth/authorize"
    _OAUTH_ACCESS_TOKEN_URL = "https://graph.renren.com/oauth/token"

    _OAUTH_URL = "https://graph.renren.com/"

    @gen.engine
    def renren_request(self, path, access_token, callback, post_args=None, **args):
        http = httpclient.AsyncHTTPClient()
        url = self._OAUTH_URL + path
        if post_args:
            #TODO as renren has not release graph resource support
            # method POST
            pass
        else:
            args.update({'oauth_token': access_token})
            http.fetch(
                url_concat(url, args),
                callback=(yield gen.Callback('_RenrenGraphMixin.renren_request'))
            )
        response = yield gen.Wait('_RenrenGraphMixin.renren_request')
        if response.error and not response.body:
            logging.warning("Error response %s fetching %s", response.error,
                    response.request.url)
            callback(None)
            return
        callback(response)
        return

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
            code, callback=(yield gen.Callback('_RenrenGraphMixin.get_authenticated_user')),
            redirect_uri=redirect_uri)

        response = yield gen.Wait('_RenrenGraphMixin.get_authenticated_user')
        if not response:
            callback(None)
            return
        try:
            user = json_decode(response.body)
        except:
            logging.warning("Error response %s fetching %s", response.body,
                    response.request.url)
            callback(None)
            return
        if 'error' in user:
            logging.warning("Error response %s fetching %s", user['error_description'],
                    response.request.url)
            callback(None)
            return

        #{{{ get session key
        self.renren_request('renren_api/session_key', user['access_token'],
                            callback=(yield gen.Callback('_RenrenGraphMixin._session_key')))
        response = yield gen.Wait('_RenrenGraphMixin._session_key')
        if response.error and not response.body:
            logging.warning("Error response %s fetching %s", response.error,
                    response.request.url)
        elif response.error:
            logging.warning("Error response %s fetching %s: %s", response.error,
                    response.request.url, response.body)
        else:
            try:
                user['session'] = json_decode(response.body)
            except:
                pass
        #}}} #TODO delete when renren graph api released
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
                   callback=(yield gen.Callback('_RenrenGraphMixin.get_access_token')))
        response = yield gen.Wait('_RenrenGraphMixin.get_access_token')

        if response.error and not response.body:
            logging.warning("Error response %s fetching %s", response.error,
                    response.request.url)
            callback(None)
            return

        callback(response)
        return

    def _oauth_consumer_token(self):
        self.require_setting("renren_client_id", "Renren Client ID")
        self.require_setting("renren_client_secret", "Renren Client Secret")
        token = dict(client_id=self.settings["renren_client_id"],
                     client_secret=self.settings["renren_client_secret"])
        return token


class RenrenRestMixin(object):
    """
    API document at http://wiki.dev.renren.com/wiki/API

    use renren_request to get resource. you need not specify paramters of 'v', 'format',
    'sig', they were built in.
    """
    _REST_SERVER = 'http://api.renren.com/restserver.do'
    _VERSION = '1.0'

    @gen.engine
    def renren_request(self, callback, **args):
        args.update({'v' : self._VERSION, 'format':'JSON'})
        token = self._oauth_consumer_token()

        args = self._generate_signature(token['client_secret'], **args)

        http = httpclient.AsyncHTTPClient()
        http.fetch(self._REST_SERVER, method='POST', body=urllib.urlencode(args),
                   callback=(yield gen.Callback('_RenrenRestMixin.renren_request')))
        response = yield gen.Wait('_RenrenRestMixin.renren_request')

        if response.error and not response.body:
            logging.warning("Error response %s fetching %s", response.error,
                    response.request.url)
            callback(None)
            return
        if response.error:
            logging.warning("Error response %s fetching %s: %s", response.error,
                    response.request.url, response.body)
        result = json_decode(response.body)
        callback(result)
        return

    def _generate_signature(self, secret, **args):
        s = ''
        for key in sorted(args):
            s += '%s=%s' % (key, args[key])
        s += secret
        sig = hashlib.md5(s).hexdigest()
        args.update({'sig':sig})
        return args

    def _oauth_consumer_token(self):
        self.require_setting("renren_client_id", "Renren Client ID")
        self.require_setting("renren_client_secret", "Renren Client Secret")
        token = dict(client_id=self.settings["renren_client_id"],
                     client_secret=self.settings["renren_client_secret"])
        return token
