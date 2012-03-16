#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012, lepture.com
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#    * Redistributions of source code must retain the above copyright
#      notice, this list of conditions and the following disclaimer.
#    * Redistributions in binary form must reproduce the above
#      copyright notice, this list of conditions and the following
#      disclaimer in the documentation and/or other materials provided
#      with the distribution.
#    * Neither the name of the author nor the names of its contributors
#      may be used to endorse or promote products derived from this
#      software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import logging
import urllib

from tornado.auth import httpclient
from tornado.options import options


class RecaptchaMixin(object):
    """Recaptcha for signup:

        class SignupHandler(BaseHandler, RecaptchaMixin):
            def get(self):
                self.write('<form method="post" action="">')
                self.write(self.xsrf_form_html())
                self.write(self.recaptcha_render())
                self.write('<button type="submit">Submit</button>')
                self.write('</form>')

            @asynchronous
            def post(self):
                self.recaptcha_validate(self._on_validate)

            def _on_validate(self, response):
                if response:
                    self.write('success')
                    self.finish()
                    return
                self.write('failed')
                self.finish()
    """

    RECAPTCHA_VERIFY_URL = "http://www.google.com/recaptcha/api/verify"

    def recaptcha_render(self):
        token = self._recaptcha_token()
        html = ('<div id="recaptcha_div"></div><script type="text/javascript" '
                'src="http://www.google.com/recaptcha/api/js/recaptcha_ajax.js'
                '"></script><script type="text/javascript">Recaptcha.create'
                '("%(key)s", "recaptcha_div", {theme: "%(theme)s",callback:'
                'Recaptcha.focus_response_field});</script>')
        return html % token

    def recaptcha_validate(self, callback):
        token = self._recaptcha_token()
        challenge = self.get_argument('recaptcha_challenge_field', None)
        response = self.get_argument('recaptcha_response_field', None)
        callback = self.async_callback(self._on_recaptcha_request, callback)
        http = httpclient.AsyncHTTPClient()
        post_args = {
            'privatekey': token['secret'],
            'remoteip': self.request.remote_ip,
            'challenge': challenge,
            'response': response
        }
        http.fetch(self.RECAPTCHA_VERIFY_URL, method="POST",
                   body=urllib.urlencode(post_args), callback=callback)

    def _on_recaptcha_request(self, callback, response):
        if response.error:
            logging.warning("Error response %s fetching %s", response.error,
                    response.request.url)
            callback(None)
            return
        verify, message = response.body.split()
        if verify == 'true':
            callback(response.body)
        else:
            logging.warning("Recaptcha verify failed %s", message)
            callback(None)

    def _recaptcha_token(self):
        token = dict(
            key=options.recaptcha_key,
            secret=options.recaptcha_secret,
            theme=options.recaptcha_theme,
        )
        return token
