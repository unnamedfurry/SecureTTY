FROM gcc:latest AS builder

WORKDIR /app

COPY . .

RUN gcc client/client.c client/text-util.c client/GuiFileSelector.c client/math.c client/network-util.c client/shared-variables.c client/cryptography.c client/chat-util.c -o client_app -lraylib -lssl -lcrypto -lGL -lm -lpthread -ldl -lrt -lX11 -lXrandr -lXinerama -lXi -lXcursor -lsodium


FROM debian:bookworm-slim

COPY --from=builder /app/myapp .

CMD ["./myapp"]