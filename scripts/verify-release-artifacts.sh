#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
settings=$(mktemp)
trap 'rm -f "$settings"' EXIT INT TERM
printf '%s\n' \
  '<settings>' \
  '  <servers>' \
  '    <server>' \
  '      <id>central</id>' \
  '      <username>dry-run</username>' \
  '      <password>dry-run</password>' \
  '    </server>' \
  '  </servers>' \
  '</settings>' \
  > "$settings"
version=$(
  "$root/mvnw" --batch-mode --no-transfer-progress \
    --file "$root/pom.xml" \
    help:evaluate \
    -Dexpression=project.version \
    -DforceStdout \
    -q
)

case "$version" in
  *-SNAPSHOT)
    echo "Release verification requires a stable project version." >&2
    exit 1
    ;;
esac

"$root/mvnw" --batch-mode --no-transfer-progress \
  --file "$root/pom.xml" \
  --settings "$settings" \
  -Prelease \
  -Dgpg.skip=true \
  -Dcentral.skipPublishing=true \
  clean deploy

for artifact in aep-core aep-json-jackson2 aep-json-jackson3 aep-agent aep-service aep-httpserver aep-servlet aep-spring-webmvc aep-platform; do
  for classifier in "" -sources -javadoc; do
    file="$root/$artifact/target/$artifact-$version$classifier.jar"
    if [ ! -s "$file" ]; then
      echo "Missing release artifact: $file" >&2
      exit 1
    fi
  done
done

if [ ! -s "$root/aep-bom/pom.xml" ]; then
  echo "Missing aep-bom POM." >&2
  exit 1
fi

for artifact in aep-core aep-json-jackson2 aep-json-jackson3 aep-agent aep-service aep-httpserver aep-servlet aep-spring-webmvc aep-platform; do
  if ! grep -q "<artifactId>$artifact</artifactId>" "$root/aep-bom/pom.xml"; then
    echo "aep-bom does not manage $artifact." >&2
    exit 1
  fi
done
