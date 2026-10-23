#!/usr/bin/env bash
set -euo pipefail
: "${RUNNER_TEMP:?}"
: "${GITHUB_ENV:?}"
umask 077
root="$RUNNER_TEMP/identity-kafka"
mkdir -p "$root"
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$root/ca.key" -out "$root/ca.crt" -subj /CN=identity-ci-ca -days 1
openssl req -newkey rsa:2048 -nodes -keyout "$root/broker.key" -out "$root/broker.csr" -subj /CN=localhost
printf 'subjectAltName=DNS:localhost,DNS:broker,IP:127.0.0.1\n' > "$root/extensions"
openssl x509 -req -in "$root/broker.csr" -CA "$root/ca.crt" -CAkey "$root/ca.key" -CAcreateserial -out "$root/broker.crt" -days 1 -extfile "$root/extensions"
password="$(openssl rand -hex 32)"
if [[ "${GITHUB_ACTIONS:-}" == "true" ]]; then printf '::add-mask::%s\n' "$password"; fi
cat > "$root/redpanda.yaml" <<'YAML'
redpanda:
  data_directory: /var/lib/redpanda/data
  node_id: 0
  seed_servers: []
  rpc_server: {address: 0.0.0.0, port: 33145}
  advertised_rpc_api: {address: localhost, port: 33145}
  kafka_api:
    - {address: 0.0.0.0, port: 29094, name: secure, authentication_method: sasl}
  advertised_kafka_api:
    - {address: localhost, port: 29094, name: secure}
  kafka_api_tls:
    - name: secure
      enabled: true
      cert_file: /tls/broker.crt
      key_file: /tls/broker.key
      truststore_file: /tls/ca.crt
      require_client_auth: false
  admin: [{address: 0.0.0.0, port: 9644}]
  enable_sasl: true
  superusers: [identity]
  developer_mode: true
YAML
chmod 600 "$root/broker.key"
docker run -d --name identity-ci-kafka --user 0:0 -p 127.0.0.1:29094:29094 -v "$root:/tls:ro" --entrypoint redpanda redpandadata/redpanda:v26.2.5@sha256:badca2d958f81da675c3055a9ecb6ebb590325582bcf16936148ffd65e96e920 --redpanda-cfg /tls/redpanda.yaml --smp 1 --memory 512M --reserve-memory 0M --overprovisioned
for attempt in $(seq 1 60); do
  if docker exec identity-ci-kafka rpk cluster health -X admin.hosts=localhost:9644 >/dev/null 2>&1; then break; fi
  sleep 1
done
if ! docker exec identity-ci-kafka rpk cluster health -X admin.hosts=localhost:9644 >/dev/null 2>&1; then
  printf 'TLS Kafka fixture did not become healthy within 60 seconds\n' >&2
  exit 1
fi
docker exec identity-ci-kafka rpk security user create identity --password "$password" --mechanism SCRAM-SHA-256 -X admin.hosts=localhost:9644
for topic in identity.events.v1 notification.commands.v1 platform.dlq.v1; do
  docker exec identity-ci-kafka rpk topic create "$topic" --partitions 6 -X brokers=localhost:29094 -X tls.enabled=true -X tls.ca=/tls/ca.crt -X user=identity -X "pass=$password" -X sasl.mechanism=SCRAM-SHA-256
done
printf 'KAFKA_BROKERS=localhost:29094\nKAFKA_TLS_CA_FILE=%s/ca.crt\nKAFKA_SASL_USERNAME=identity\nKAFKA_SASL_PASSWORD=%s\n' "$root" "$password" >> "$GITHUB_ENV"
