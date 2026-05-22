# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project overview

A WAF (Web Application Firewall) for Nginx/OpenResty written in Lua (~420 lines). It runs in the Nginx `access_by_lua_file` phase and sequentially checks each request against rule files (regex patterns), logging and blocking matches.

## Architecture

```
nginx.conf (http block)
  ├── init_by_lua_file → waf/init.lua     — defines all check functions (loaded once at startup)
  └── access_by_lua_file → waf/access.lua — calls waf_main() on every request

Request flow through waf_main() in access.lua:
  white_ip_check → white_url_check → black_ip_check → user_agent_attack_check
  → cc_attack_check → cookie_attack_check → url_attack_check
  → url_args_attack_check → post_attack_check
```

Each check reads its corresponding rule file from `rule-config/`, then iterates rules with `ngx.re.find(str, rule, "jo")`. First match short-circuits — whitelist checks allow the request through; all others block it.

## Key files

| File | Role |
|------|------|
| `waf/config.lua` | All configuration: on/off toggles per check, CC rate limit, log/output paths, custom 403 HTML. Uses global `config_*` variables. |
| `waf/access.lua` | Entry point. Requires `init`, calls `waf_main()`. |
| `waf/init.lua` | Defines the 9 check functions (`white_ip_check`, `black_ip_check`, `white_url_check`, `cc_attack_check`, `cookie_attack_check`, `url_attack_check`, `url_args_attack_check`, `user_agent_attack_check`, `post_attack_check`). Requires `config` and `lib`. |
| `waf/lib.lua` | Shared utilities: `get_client_ip()` (checks X_real_ip → X_Forwarded_For → remote_addr), `get_rule(filename)` (reads a rule file into a table), `log_record()` (writes JSON log lines), `waf_output()` (renders 403 HTML or redirect). |
| `waf/rule-config/*.rule` | Plain-text rule files, one regex per line. `ngx.re.find` with `"jo"` flags (JIT-compiled, cached). |

## Rule files

- `whiteip.rule` / `blackip.rule` — IP whitelist/blacklist (both empty by default)
- `whiteurl.rule` — URL path whitelist (default: only `/123/`)
- `url.rule` — Sensitive paths/extensions to block
- `args.rule` — Query string attack patterns (SQLi, XSS)
- `post.rule` — POST body attack patterns
- `cookie.rule` — Cookie attack patterns
- `useragent.rule` — Malicious crawler/scanner UA patterns

## Nginx integration (required directives)

```nginx
lua_shared_dict limit 50m;
lua_package_path "/usr/local/openresty/nginx/conf/waf/?.lua";
init_by_lua_file  "/usr/local/openresty/nginx/conf/waf/init.lua";
access_by_lua_file "/usr/local/openresty/nginx/conf/waf/access.lua";
```

The `resty` library must be symlinked: `ln -s /usr/local/openresty/lualib/resty/ /usr/local/openresty/nginx/conf/waf/resty`

## Configuration

All settings are in `waf/config.lua` as global Lua variables prefixed `config_`. Key ones:

- `config_waf_enable` — master kill switch (`"on"`/`"off"`)
- `config_cc_rate = "10/60"` — 10 requests per 60 seconds per IP+URI
- `config_waf_output = "html"` — block response type (`"html"` or `"redirect"`)
- `config_rule_dir` / `config_log_dir` — paths for rule files and JSON logs

## No build/lint/test infrastructure

This is pure Lua deployed directly into Nginx. There is no build system, package manager, linter config, or test framework. To test changes, deploy to an OpenResty instance and verify with `nginx -t` then `nginx -s reload`.
