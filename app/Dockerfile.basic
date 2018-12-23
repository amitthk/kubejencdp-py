FROM centos:latest
MAINTAINER amitthk
RUN yum -y update && yum -y install gcc python-setuptools python-devel openldap-devel && \
    easy_install pip supervisor
ARG APP_HOME=/opt/pyfln_auth_api
ENV APP_HOME $APP_HOME
COPY app ${APP_HOME}/
COPY uid_entrypoint ${APP_HOME}

RUN chmod 0755 ${APP_HOME}/uid_entrypoint && \
    python -m pip install -r ${APP_HOME}/requirements.txt
EXPOSE 80

WORKDIR ${APP_HOME}
ENTRYPOINT ["./uid_entrypoint"]
CMD ["gunicorn","-b","0.0.0.0:80","wsgi:app"]