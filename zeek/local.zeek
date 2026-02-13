# Load default scripts
@load misc/loaded-scripts
@load tuning/defaults
@load misc/capture-loss
@load frameworks/software/vulnerable
@load frameworks/software/version-changes
@load protocols/conn/known-services
@load protocols/ssl/known-certs

# ENABLE JSON LOGGING (Critical for Spark)
@load policy/tuning/json-logs.zeek

# Define which logs you want (Conn log is the most important for NIDS)
redef Log::default_logdir = "/zeek-logs";