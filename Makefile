.PHONY: dev api ui ui-build start prod health migrate prune backup

# Dev: run API + Vite with sane env
dev:
	API_BASE=http://127.0.0.1:5000 REQUIRE_AUTH=1 bash scripts/run_all_dev.sh

api:
	REQUIRE_AUTH=1 python3 api.py

ui:
	cd ui && npm run dev

ui-build:
	cd ui && npm ci && npm run build

# Start API in a production-ish way (Gunicorn, access logs to stdout)
start:
	gunicorn -b 127.0.0.1:5000 -w 2 -k gthread --threads 4 --timeout 60 --access-logfile - api:app

# Simulated prod (NGINX reverse-proxy to API + static UI)
prod:
	sudo nginx -c $(PWD)/ops/nginx.conf -g 'daemon off;'

health:
	curl -sS http://127.0.0.1:5000/healthz | jq .

migrate:
	bash scripts/migrate_db.sh

prune:
	bash scripts/retention_now.sh 30 30

backup:
	bash scripts/backup_db.sh
