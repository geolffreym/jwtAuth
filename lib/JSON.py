###############################################################################
#
# The MIT License (MIT)
#
# Copyright (c) Geolffrey Mena
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#
###############################################################################

__author__ = 'Geolffrey'

import json
import datetime
from django import http


class JSON(object):
    @staticmethod
    def render_to_response(context, code=200):
        """Returns a JSON response containing 'context' as payload"""
        return JSON.get_json_response(
            JSON.convert_context_to_json(context), code
        )

    @staticmethod
    def get_json_response(content, code, **kwargs):
        """Construct an `HttpResponse` object."""
        response = http.HttpResponse(content, content_type='application/json', **kwargs)
        response.status_code = code
        return response

    @staticmethod
    def convert_context_to_json(context):
        """Convert the context dictionary into a JSON object"""
        return json.dumps(context, default=JSON.default, sort_keys=True, ensure_ascii=True)

    @staticmethod
    def default(o):
        if type(o) is datetime.date or type(o) is datetime.datetime:
            return o.isoformat()

    @staticmethod
    def dump_json_post(request):
        json_str = request.body.decode(encoding='UTF-8')
        return json.loads(json_str)
