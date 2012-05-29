#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012, Hsiaoming Yang
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


import base64
import functools
from tornado import httpclient


class BaseUpyun(object):
    def __init__(self, bucket_with_dir, username, password, static_url=None):
        splits = bucket_with_dir.split('/')
        bucket = splits[0]
        if len(splits) > 1:
            directory = '/'.join(splits[1:])
        else:
            directory = None

        self.url = 'http://v0.api.upyun.com/%s/' % bucket_with_dir
        self.username = username
        self.password = password
        if static_url:
            self.static_url = static_url
        elif directory:
            self.static_url = 'http://%s.b0.upaiyun.com/%s/' % \
                    (bucket, directory)
        else:
            self.static_url = 'http://%s.b0.upaiyun.com/' % bucket

    def basic_auth_header(self):
        auth = base64.b64encode('%s:%s' % (self.username, self.password))
        headers = {'Authorization': 'Basic %s' % auth}
        return headers

    def get_usage(self, callback=None):
        url = self.url + '?usage'
        http = httpclient.AsyncHTTPClient()
        http.fetch(url, method='GET', headers=self.basic_auth_header(),
                   callback=callback)
        return

    def upload(self, body, filename, callback=None):
        url = self.url + filename
        http = httpclient.AsyncHTTPClient()
        http.fetch(
            url, method='PUT', headers=self.basic_auth_header(), body=body,
            callback=functools.partial(self._on_upload, callback, filename))
        return

    def _on_upload(self, callback, filename, response):
        if not callback:
            return
        if response.error:
            callback(None)
            return
        callback(self.static_url + filename)
        return
