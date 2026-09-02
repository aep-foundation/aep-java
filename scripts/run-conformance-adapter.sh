#!/bin/sh
set -eu

role=${1:?usage: run-conformance-adapter.sh agent|platform|service}
classpath_file=${AEP_CONFORMANCE_CLASSPATH:-.conformance/classpath}
dependencies=$(tr -d '\n' < "$classpath_file")

exec java \
  -classpath "tools/aep-conformance/target/classes:$dependencies" \
  foundation.aep.conformance.ConformanceAdapter "$role"
