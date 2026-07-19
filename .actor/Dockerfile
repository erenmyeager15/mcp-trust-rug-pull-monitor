FROM apify/actor-node:20

WORKDIR /usr/src/app
COPY --chown=myuser package.json package-lock.json ./
RUN npm ci --include=dev --omit=optional --no-audit --no-fund
COPY --chown=myuser tsconfig.json ./
COPY --chown=myuser src ./src
RUN node ./node_modules/typescript/bin/tsc \
    && npm prune --omit=dev --omit=optional --no-audit --no-fund
CMD ["node", "dist/main.js"]
