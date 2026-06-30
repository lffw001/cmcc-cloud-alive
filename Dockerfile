FROM node:20-bookworm-slim

WORKDIR /app

RUN apt-get update \
  && apt-get install -y --no-install-recommends iproute2 procps tcpdump ca-certificates \
  && rm -rf /var/lib/apt/lists/*

COPY package.json ./
COPY bin ./bin
COPY lib ./lib
COPY scripts ./scripts
COPY tests ./tests
COPY docs ./docs
COPY README.md ./

RUN chmod +x /app/bin/cmcc-cloud-alive.js && npm run check

ENTRYPOINT ["node", "/app/bin/cmcc-cloud-alive.js"]
CMD ["help"]
