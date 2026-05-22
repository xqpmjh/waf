--waf core lib
require 'config'

--Get the client IP
function get_client_ip()
    local CLIENT_IP = ngx.req.get_headers()["X_real_ip"]
    if CLIENT_IP == nil then
        CLIENT_IP = ngx.req.get_headers()["X_Forwarded_For"]
    end
    if CLIENT_IP == nil then
        CLIENT_IP  = ngx.var.remote_addr
    end
    if CLIENT_IP == nil then
        CLIENT_IP  = "unknown"
    end
    return CLIENT_IP
end

--Get the client user agent
function get_user_agent()
    local USER_AGENT = ngx.var.http_user_agent
    if USER_AGENT == nil then
       USER_AGENT = "unknown"
    end
    return USER_AGENT
end

--Rule file cache (loaded once per worker on first access)
local rule_cache = {}

--Get WAF rule
function get_rule(rulefilename)
    if rule_cache[rulefilename] then
        return rule_cache[rulefilename]
    end
    local io = require 'io'
    local RULE_PATH = config_rule_dir
    local RULE_FILE = io.open(RULE_PATH..'/'..rulefilename,"r")
    if RULE_FILE == nil then
        return nil
    end
    local RULE_TABLE = {}
    for line in RULE_FILE:lines() do
        table.insert(RULE_TABLE,line)
    end
    RULE_FILE:close()
    rule_cache[rulefilename] = RULE_TABLE
    return RULE_TABLE
end

--WAF log record for json,(use logstash codec => json)
--Keeps log file handle open across requests; only reopens on date change
local log_file_handle = nil
local log_file_date = nil

function log_record(method,url,data,ruletag)
    local cjson = require("cjson")
    local LOG_PATH = config_log_dir
    local CLIENT_IP = get_client_ip()
    local USER_AGENT = get_user_agent()
    local SERVER_NAME = ngx.var.host
    local LOCAL_TIME = ngx.localtime()
    local log_json_obj = {
                 client_ip = CLIENT_IP,
                 local_time = LOCAL_TIME,
                 server_name = SERVER_NAME,
                 user_agent = USER_AGENT,
                 attack_method = method,
                 req_url = url,
                 req_data = data,
                 rule_tag = ruletag,
              }
    local LOG_LINE = cjson.encode(log_json_obj)
    local today = ngx.today()
    if log_file_date ~= today then
        if log_file_handle then
            log_file_handle:close()
        end
        local io = require 'io'
        local LOG_NAME = LOG_PATH..'/'..today.."_waf.log"
        log_file_handle = io.open(LOG_NAME,"a")
        log_file_date = today
    end
    if log_file_handle == nil then
        return
    end
    log_file_handle:write(LOG_LINE.."\n")
    log_file_handle:flush()
end

--WAF return
function waf_output()
    if config_waf_output == "redirect" then
        ngx.redirect(config_waf_redirect_url, 301)
    else
        ngx.header.content_type = "text/html"
        ngx.status = ngx.HTTP_FORBIDDEN
        ngx.say(config_output_html)
        ngx.exit(ngx.status)
    end
end
