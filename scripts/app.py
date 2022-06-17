#!/usr/bin/env python3

import sys, os

from bottle import route, static_file, run, post, request
import zkcreds
import base64

# Move current directory to file
os.chdir(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Directories where various webpages are stored
STATIC_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'static')

# TODO: Get proving and verifying keypair from somewhere


@route('/')
@route('/index.html')
def index():
    return static_file('index.html', root=STATIC_PATH)

@route('/issue-req')
@route('/issue-req-html')
def issue_req():
    return static_file('issue-req.html', root=STATIC_PATH)

@post('/issue-req')
@post('/issue-req.html')
def issue_req_validate():
    fields = ['attrs']
    # TODO: JSON parsing for valid format
    # TODO: Feed JSON-encoded credential into Rust bindings to get base64
    isu_req = base64.b64encode(request.forms['attrs'].encode('utf-8'))

    return '''
        <div style="text-align: center; padding: 0% 10% 0% 10%;">
            <form action="/issue-grant.html" method="POST">

                <h1><tt>zkcreds</tt> Application</h1>
                <h3>Issuance Request</h3>

                <p>Your issuance request is:</p>
                <p><tt>{req}</tt></p>
                <p>Store this issuance request in a safe place, then send it to your issuer! (this will redirect you to <tt>/issue-grant</tt>)</p>

                <input type="submit" value="Send Request" />
            </form>
        </div>
    '''.format(req=isu_req.decode())


if __name__ == '__main__':
    # TODO: Host on a public-facing webpage
    run(host='localhost', port=5000, debug=True, reloader=True)
