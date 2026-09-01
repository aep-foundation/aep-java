.PHONY: clean format format-check verify

clean:
	./mvnw clean

format:
	./mvnw spotless:apply

format-check:
	./mvnw spotless:check

verify:
	./mvnw verify
