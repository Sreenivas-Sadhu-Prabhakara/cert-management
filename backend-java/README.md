# cert-management — Java/Spring Boot backend (:8081)

Build: `mvn -q package` (JDK 17+; tested on Temurin 25)

Run: `set -a; source ../.env; set +a; export PORT=8081 BACKEND_NAME=java; java -jar target/cert-management-java-1.0.0.jar`

Verify: `../scripts/smoke.sh 8081` (needs OpenSSL 3.x on PATH, or `OPENSSL=/path/to/openssl3`)
