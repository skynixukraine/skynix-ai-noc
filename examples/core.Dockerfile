FROM python:3.12-slim
WORKDIR /app
COPY core/pyproject.toml /app/
RUN pip install -U pip && pip install .
COPY core/ai_noc_core /app/ai_noc_core
COPY migrations /app/migrations
EXPOSE 8080
CMD python -c "import os, psycopg; \
conn=psycopg.connect(os.environ['DATABASE_URL']); \
cur=conn.cursor(); \
cur.execute(open('/app/migrations/001_initial.sql','r').read()); \
conn.commit(); conn.close()" && \
    uvicorn ai_noc_core.main:app --host 0.0.0.0 --port 8080

