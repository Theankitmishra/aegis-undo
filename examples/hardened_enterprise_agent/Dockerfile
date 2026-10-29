FROM python:3.11-slim
RUN useradd -m -u 10001 aegisagent
WORKDIR /app
COPY --chown=aegisagent:aegisagent agent_worker.py /app/
USER aegisagent
CMD ["python", "agent_worker.py"]
