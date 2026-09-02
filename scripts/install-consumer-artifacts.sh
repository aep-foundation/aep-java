#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
  echo "Usage: $0 REPOSITORY VERSION" >&2
  exit 2
fi

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
repository=$1
version=$2

"$root/mvnw" --batch-mode --no-transfer-progress \
  --file "$root/pom.xml" \
  -DskipTests \
  package

install_artifact() {
  file=$1
  pom=$2
  "$root/mvnw" --batch-mode --no-transfer-progress \
    org.apache.maven.plugins:maven-install-plugin:3.1.4:install-file \
    -Dfile="$file" \
    -DpomFile="$pom" \
    -DlocalRepositoryPath="$repository"
}

install_artifact "$root/pom.xml" "$root/pom.xml"
install_artifact "$root/aep-bom/pom.xml" "$root/aep-bom/pom.xml"
for artifact in aep-core aep-json-jackson2 aep-json-jackson3 aep-agent aep-service aep-httpserver aep-servlet aep-spring-webmvc aep-platform; do
  install_artifact \
    "$root/$artifact/target/$artifact-$version.jar" \
    "$root/$artifact/pom.xml"
done
