# The MIT License
# SPDX short identifier: MIT
# Further resources on the MIT License
# Copyright 2018 Amit Thakur - amitthk - <e.amitthakur@gmail.com>
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
# The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
FROM centos/python-27-centos7

ARG APP_HOME=/opt/app-root/src
ARG USER_NAME=pyflnuser
ENV USER_NAME ${USER_NAME}
ENV APP_HOME $APP_HOME

#env from original 
ENV APP_ROOT /opt/app-root
ENV PIP_NO_CACHE_DIR off
ENV LIBRARY_PATH /opt/rh/httpd24/root/usr/lib64
ENV PYTHONUNBUFFERED 1
ENV NODEJS_SCL rh-nodejs8
ENV LC_ALL en_US.UTF-8
ENV PYTHONIOENCODING UTF-8
ENV LD_LIBRARY_PATH /opt/rh/python27/root/usr/lib64:/opt/rh/rh-nodejs8/root/usr/lib64:/opt/rh/httpd24/root/usr/lib64
ENV VIRTUAL_ENV /opt/app-root
ENV PYTHON_VERSION 2.7
ENV PATH /opt/app-root/bin:/opt/rh/python27/root/usr/bin:/opt/rh/rh-nodejs8/root/usr/bin:/opt/rh/httpd24/root/usr/bin:/opt/rh/httpd24/root/usr/sbin:/opt/app-root/src/.local/bin/:/opt/app-root/src/bin:/opt/app-root/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ENV STI_SCRIPTS_URL image:///usr/libexec/s2i
ENV PWD /opt/app-root/src
ENV STI_SCRIPTS_PATH /usr/libexec/s2i
ENV LANG en_US.UTF-8
ENV SUMMARY Platform for building and running Python 2.7 applications
ENV PS1 (app-root)
ENV HOME /opt/app-root/src
ENV SHLVL 1
ENV PYTHONPATH /opt/rh/rh-nodejs8/root/usr/lib/python2.7/site-packages
ENV XDG_DATA_DIRS /opt/rh/python27/root/usr/share:/usr/local/share:/usr/share
ENV PKG_CONFIG_PATH /opt/rh/python27/root/usr/lib64/pkgconfig:/opt/rh/httpd24/root/usr/lib64/pkgconfig



# ARG PIP_INDEX=https://atksv.mywire.org:8993/nexus/repository/pypi-all/simple
# ENV PIP_INDEX ${PIP_INDEX}

USER root

RUN groupadd -g 10000 ${USER_NAME} && \
    useradd --no-log-init -u 10000 -g ${USER_NAME} -ms /bin/bash ${USER_NAME}
    # && echo '' >> /etc/resolv.conf && echo "nameserver 8.8.8.8" >> /etc/resolv.conf
    # rm /etc/yum.repos.d/Cen* && \
    # cp /tmp/centos.repo /etc/yum.repos.d/
 #   update-ca-trust force-enable
#   mkdir -p ~/.pip && cp /tmp/pip/pip.conf ~/.pip/pip.conf && \


RUN yum -y update && \
  yum downgrade -y glibc glibc-common glibc-devel glibc-headers && \
  yum install -y gcc unzip python-setuptools python-ldap

COPY files /tmp/
COPY app ${APP_HOME}/

RUN bash -c "cd ${APP_HOME} && python -m pip install -r requirements.txt"

RUN cp /tmp/uid_entrypoint ${APP_HOME}/ && \
  chmod -R 0775 ${APP_HOME} && \
  chown -R ${USER_NAME}:${USER_NAME} ${APP_HOME} && \
  chmod -R g=u /etc/passwd

EXPOSE 8000

WORKDIR ${APP_HOME}

ENTRYPOINT ["./uid_entrypoint"]

CMD ["gunicorn", "-b", "0.0.0.0:8000","wsgi:app"]