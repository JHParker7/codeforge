docker build -t gatekeeper:test src/gatekeeper
cd ../..
cd infra/local
docker compose up
cd ../..
pytest tests/integration_tests
docker compose down -
pytest tests/integration_tests
docker compose down -v
