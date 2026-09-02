.PHONY: clean format format-check interoperability verify

clean:
	./mvnw clean

format:
	./mvnw spotless:apply

format-check:
	./mvnw spotless:check

interoperability:
	./scripts/run-node-interoperability.sh

verify:
	./mvnw verify
