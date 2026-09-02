#!/bin/sh
set -eu

specs_dir=${AEP_SPECS_DIR:-../aep-specs}
output_dir=${AEP_CONFORMANCE_OUTPUT:-.conformance/reports}
implementation_version=${AEP_JAVA_VERSION:-$(./mvnw --quiet --batch-mode --no-transfer-progress \
  help:evaluate -Dexpression=project.version -DforceStdout)}
implementation_version=${implementation_version%-SNAPSHOT}
implementation_version=${implementation_version#v}
manifest=.conformance/capability-manifest.json

./mvnw --quiet --batch-mode --no-transfer-progress -DskipTests install
mkdir -p "$output_dir"
./mvnw --quiet --batch-mode --no-transfer-progress \
  -f tools/aep-conformance/pom.xml \
  -DincludeScope=runtime \
  -Dmdep.outputFile="$PWD/.conformance/classpath" \
  dependency:build-classpath

printf '%s\n' "{\"claims\":[{\"profiles\":[\"core-http\",\"claims\",\"api-key\",\"basic\",\"oauth-bearer\"],\"role\":\"agent\"},{\"profiles\":[\"platform-hosted-identity\"],\"role\":\"platform\"},{\"profiles\":[\"core-http\",\"claims\",\"api-key\",\"basic\",\"oauth-bearer\"],\"role\":\"service\"}],\"implementation\":{\"name\":\"aep-java\",\"version\":\"$implementation_version\"},\"manifest_version\":\"1\"}" > "$manifest"

for role in agent platform service; do
  BUNDLE_GEMFILE="$specs_dir/ietf/Gemfile" bundle exec ruby "$specs_dir/ietf/scripts/run_conformance.rb" \
    --role "$role" \
    --manifest "$manifest" \
    --output "$output_dir/$role.json" \
    -- ./scripts/run-conformance-adapter.sh "$role"
done
