#!/bin/bash

# modules/secure-vps/lib/baseline.sh
# Service Allow/Block Lists

# Regex for Critical Services (Should be Internal)
# Redis(6379), Postgres(5432), MySQL(3306), Mongo(27017), Elastic(9200), Docker(2375/6)
BASELINE_PORTS_CRITICAL="^(6379|543[0-9]|3306|27017|9200|237[0-9])$"

# Regex for Expected Public Services
# Web(80, 443), VoIP/RTC(3478, 7880, 7881), SSH(22 - handled separately usually but OK here)
BASELINE_PORTS_EXPECTED="^(80|443|3478|7880|7881)$"
