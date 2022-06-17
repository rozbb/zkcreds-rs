#!/usr/bin/env python3

import sys, os

from bottle import route, static_file, run, post, request, redirect, route
import urllib.parse

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
# Displays page which clicks to route to /issuance/request
def index():
    return static_file('index.html', root=STATIC_PATH)


@route('/issuance/request')
@route('/issue-req.html')
# Displays page where user enters cred and submits POST request to /issuance/request
def issue_req():
    return static_file('issue-req.html', root=STATIC_PATH)


@post('/issuance/request')
@post('/issue-req.html')
# Formulates issuance request and submits POST request to /issuance/grant
def issue_req_validate():
    # TODO: JSON parsing for valid format
    # TODO: Feed JSON-encoded credential into Rust bindings to get base64
    isu_req = base64.b64encode(request.forms['attrs'].encode('utf-8'))

    return '''
        <div style="text-align: center; padding: 0% 10% 0% 10%;">
            <form action="/issuance/grant" method="POST">

                <h1><tt>zkcreds</tt> Application</h1>
                <h3>Issuance Request</h3>

                <p>Your issuance request is:</p>
                <p><tt>{req}</tt></p>
                <p>Store this issuance request in a safe place, then send it to an issuer by clicking the button below!</p>

                <input type="submit" value="Send Request" />
            </form>
        </div>
    '''.format(req=isu_req.decode())


@route('/issuance/grant')
@route('/issuance/grant/info')
@route('/issue-grant-info.html')
def issue_grant():
    return static_file('issue-grant-info.html', root=STATIC_PATH)


@post('/issuance/grant')
# Parses credential from request, verifies whether it meets the criteria and, if so, sends GET request with cred in query string (TODO: POST)
def issue_grant_validate():
    # TODO: Feed base64-encoded request into Rust bindings to get base64-encoded credential (or failure)
    verifies = True
    cred = base64.b64encode(b'cred')

    if verifies:
        return redirect('/issuance/grant/success?cred={}'.format(urllib.parse.quote(cred.decode())))
    else:
        return redirect('/issuance/grant/fail')


@route('/issuance/grant/success')
# On success, displays now-issued credential
def issue_grant_success():
    credential = urllib.parse.unquote(request.query.get('cred', ''))

    # TODO: Continue on to show attributes, perhaps
    return '''
        <div style="text-align: center; padding; 0% 10% 0% 10%;">
	    <h1><tt>zkcreds</tt> Application</h1>
		<!-- Blue that contrasts for color vision deficiencies -->
		<h3>Granting Issuance: <font style="color: #005AB5;">Success!</font></h3>

                <p>Your newly-issued credential is:</p>
                <p><tt>{cred}</tt></p>
                <p>Remember this credential if you ever need to show it to someone else!</p>
                <br />

		<p><strong><a href="/">Click here</a> to try again.</strong></p>
        </div>
    '''.format(cred=credential)


@route('/issuance/grant/fail')
@route('/issue-grant-fail.html')
# On failure, displays error message and clicks back to start of demo
def issue_grant_failure():
    return static_file('issue-grant-fail.html', root=STATIC_PATH)


if __name__ == '__main__':
    # TODO: Host on a public-facing webpage
    run(host='localhost', port=5000, debug=True, reloader=True)
