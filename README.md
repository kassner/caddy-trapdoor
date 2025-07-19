# caddy-trapdoor

A Caddy module to tell web scanners to ~~sod off~~ cool down.

## Installation

```bash
xcaddy build --with github.com/kassner/caddy-trapdoor
```

## Configuration

- `action` (default: `403`): defines which HTTP status code to return;
- `duration` (default: `1h`): defines for how long **ANY** request from an infringing client will be blocked;
- `match`: defines how to match an infringing client. It accepts any [standard matcher](https://caddyserver.com/docs/caddyfile/matchers#standard-matchers);
- `expunger_interval` (default: `5m`): defines how often the expunger runs;

```Caddyfile
(trapdoor) {
  trapdoor {
    action 429
    duration 1h
    expunger_interval 5m
    match {
      path /.aws/config
      path /.aws/credentials
      path /.env
      path /.env.*
      path /.git/config
      path /.idea/workspace.xml
      path /.vscode/settings.json
      path /wp-admin/*
      path /wp-login.php
      path /xmlrpc.php
    }
  }
}

example.com {
  root /var/www/example.com
  import trapdoor
}

example.net {
  root /var/www/example.net
  import trapdoor
}
```

## Implementation details

1. Once a request is matched, the infringing client's IP address is put on a list;
2. **ALL** requests from infringing IP addresses will return the same HTTP status defined in `action`, for the `duration` configured;
3. There is one global infringing IP address list, shared between any virtual host with the `trapdoor` configured;
4. An IP address matched will be blocked from **ANY** virtual host with the `trapdoor` configured;

## Problem statement

Every day, my servers see random IP addresses bursting hundreds of requests to some known paths in search of credentials, logs or vulnerabilities:

```
2025-07-19 01:04:29 UTC  404  GET /.env.local
2025-07-19 01:04:29 UTC  404  GET /.env.dev
2025-07-19 01:04:30 UTC  404  GET /.env.prod
2025-07-19 01:04:30 UTC  404  GET /.env.stage
2025-07-19 01:04:30 UTC  404  GET /.env.bak
2025-07-19 01:04:30 UTC  404  GET /.env.old
2025-07-19 01:04:30 UTC  404  GET /config/.env
2025-07-19 01:04:30 UTC  404  GET /config/config.env
2025-07-19 01:04:30 UTC  404  GET /app/.env
2025-07-19 01:04:30 UTC  404  GET /admin/.env
2025-07-19 01:04:30 UTC  404  GET /api/.env
2025-07-19 01:04:30 UTC  404  GET /apps/.env
2025-07-19 01:04:30 UTC  404  GET /server/.env
2025-07-19 01:04:30 UTC  404  GET /backend/.env
2025-07-19 01:04:30 UTC  404  GET /aws/credentials
2025-07-19 01:04:30 UTC  404  GET /.aws/credentials
2025-07-19 01:04:41 UTC  404  GET /.aws/config
2025-07-19 01:04:41 UTC  404  GET /config/aws.yml
2025-07-19 01:04:41 UTC  404  GET /config/aws.json
2025-07-19 01:04:41 UTC  404  GET /docker-compose.yml
2025-07-19 01:04:41 UTC  404  GET /config/config.json
2025-07-19 01:04:41 UTC  404  GET /config.yaml
2025-07-19 01:04:41 UTC  404  GET /secrets.json
2025-07-19 01:04:41 UTC  404  GET /secrets.yml
2025-07-19 01:04:41 UTC  404  GET /credentials.json
2025-07-19 01:04:41 UTC  404  GET /.git-credentials
2025-07-19 01:04:41 UTC  404  GET /.git/config
2025-07-19 01:04:42 UTC  404  GET /.gitignore
2025-07-19 01:04:42 UTC  404  GET /.gitlab-ci.yml
2025-07-19 01:04:42 UTC  404  GET /.github/workflows/
2025-07-19 01:04:42 UTC  404  GET /.idea/workspace.xml
2025-07-19 01:04:42 UTC  404  GET /.vscode/settings.json
2025-07-19 01:04:42 UTC  404  GET /storage/logs/laravel.log
2025-07-19 01:04:42 UTC  404  GET /storage/logs/error.log
2025-07-19 01:04:42 UTC  404  GET /logs/debug.log
2025-07-19 01:04:42 UTC  404  GET /logs/app.log
2025-07-19 01:04:42 UTC  404  GET /debug.log
2025-07-19 01:04:42 UTC  404  GET /error.log
2025-07-19 01:04:42 UTC  404  GET /.DS_Store
2025-07-19 01:04:42 UTC  404  GET /backup.zip
2025-07-19 01:04:42 UTC  404  GET /.backup
2025-07-19 01:04:42 UTC  404  GET /db.sql
2025-07-19 01:04:43 UTC  404  GET /dump.sql
2025-07-19 01:04:43 UTC  404  GET /database.sql
2025-07-19 01:04:43 UTC  404  GET /backup.tar.gz
```

While they are mostly harmless to my system, they are quite annoying, and in some configurations they cause unexpected load. It's also not easy to block such bursts, as they come from random IP addresses (even residential), and fail2ban cannot react fast enough.
