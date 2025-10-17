FROM python:slim AS app
RUN pip install --no-cache-dir pycryptodome
FROM pwn.red/jail
COPY --from=app / /srv
COPY chall.py /srv/app/run
RUN chmod 777 /srv/app/run
COPY flag.txt /srv/app/
RUN chmod 777 /srv/app/flag.txt
ENV JAIL_TMP_SIZE=65536 JAIL_MEM=20M JAIL_PIDS=10 JAIL_TIME=300