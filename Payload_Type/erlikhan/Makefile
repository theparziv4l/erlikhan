BINARY_NAME?=erlikhan
RABBITMQ_HOST?="127.0.0.1"
RABBITMQ_PASSWORD?="PqR9XJ957sfHqcxj6FsBMj4p"
MYTHIC_SERVER_HOST?="127.0.0.1"
MYTHIC_SERVER_GRPC_PORT?="17444"

# Mythic bind-mounts InstalledServices/erlikhan over /Mythic at runtime,
# hiding everything baked into the image there. The service binary must
# therefore live at /erlikhan (outside the mount); sources stay visible
# under /Mythic, so run keeps cwd=/Mythic. Same pattern as the stock
# http profile and Apollo (binaries stashed at /).
build:
	cd container && go mod download && go mod tidy && GOOS=linux go build -o /${BINARY_NAME} .

run:
	cd /Mythic && /${BINARY_NAME}

local:
	cd container && go build -o ${BINARY_NAME} .

run_custom: local
	cd container && \
	DEBUG_LEVEL="trace" \
	RABBITMQ_HOST=${RABBITMQ_HOST} \
	RABBITMQ_PASSWORD=${RABBITMQ_PASSWORD} \
	MYTHIC_SERVER_HOST=${MYTHIC_SERVER_HOST} \
	MYTHIC_SERVER_GRPC_PORT=${MYTHIC_SERVER_GRPC_PORT} \
	./${BINARY_NAME}
