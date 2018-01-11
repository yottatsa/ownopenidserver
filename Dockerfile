FROM alpine:latest
RUN apk add --no-cache ca-certificates uwsgi uwsgi-python python py-setuptools py-flup py-lxml; easy_install-2.7 pip
RUN pip install -U pip; pip install Jinja2 html5lib python-openid web.py
ADD openidserver /opt/openidserver
EXPOSE 3031 9191
CMD mkdir -p /opt/openidserver/sstore; chown -R uwsgi: /opt/openidserver/sstore; exec uwsgi --plugins-dir /usr/lib/uwsgi/ --need-plugin python --uid uwsgi --gid uwsgi --socket 0.0.0.0:3031 --chdir /opt/openidserver --wsgi-file wsgi.py --master --processes 4 --threads 2 -b 32768 --stats 0.0.0.0:9191
