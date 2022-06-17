#!/usr/bin/env python3

import sys, os

from bottle import route, static_file, run
import zkcreds

# Move current directory to file
os.chdir(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Directories where various webpages are stored
STATIC_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'static')
CSS_PATH = os.path.join(STATIC_PATH, 'css')


@route('/')
def index():
    return 'This test application is using the <tt>zkcreds</tt> Rust library!'

@route('/static/<filepath:path>')
def serve_static(filepath):
    return static_file(filepath, root=STATIC_PATH)

@route('/issue-req')
def issue_req():
    return '''
        <div style="text-align: center;">
            <form method="POST">

                <h1><tt>zkcreds</tt> Application</h1>

                <label for="attrs" style="text-align: center;"><p><strong>Attributes (JSON):</strong></p></label>
                <textarea id="attrs" style="height: 50%; width: 50%" name="attrs" type="file" placeholder="{\n\t&quot;foo&quot;: &quot;bar&quot;,\n\t&quot;baz&quot;: 0\n}"></textarea>
                <br /><br />

                <input type="submit" />
            </form>
        </div>
    '''

#app = bottle.default_app()

if __name__ == '__main__':
    # TODO: Host elsewhere
    print(STATIC_PATH)
    run(host='localhost', port=5000, debug=True, reloader=True)
