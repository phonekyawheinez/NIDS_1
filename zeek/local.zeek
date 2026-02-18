# --- LOAD CORE SCRIPTS ---
@load base/utils/site
@load base/protocols/conn
@load base/protocols/http
@load policy/tuning/json-logs.zeek

# --- OPTIMIZATIONS ---
redef LogAscii::use_json = T;
redef LogAscii::json_timestamps = JSON::TS_ISO8601;
redef LogAscii::path_prefix = "/zeek-logs/";
redef Log::default_rotation_interval = 0secs;