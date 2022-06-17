#!/usr/bin/env python3

import sys, os

from bottle import route, static_file, run
import zkcreds

# Move current directory to file
os.chdir(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Directories where various webpages are stored
STATIC_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'static')

@route('/')
def index():
    return 'This test application is using the <tt>zkcreds</tt> Rust library!'

@route('/issue-req')
def issue_req():
    return static_file('issue-req.html', root=STATIC_PATH)

#@route('/static/<filename:path>')
#def serve_stylesheet(filename):
#    return static_file('{}.css'.format(filename), root=CSS_PATH)

#app = bottle.default_app()

if __name__ == '__main__':
    # TODO: Host elsewhere
    print(STATIC_PATH)
    run(host='localhost', port=5000, debug=True, reloader=True)
