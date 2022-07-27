#!/bin/sh

/script/wait-for selenium-server:4444 --timeout=30 -- echo selenium-server ok
/script/wait-for proxy:3000 --timeout=30 -- echo proxy ok

gunicorn --keep-alive 10 -k gevent --bind 0.0.0.0:8000 app:app