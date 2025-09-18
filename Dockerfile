FROM node:22-alpine AS base

RUN npm install pnpm -g

FROM base AS builder

WORKDIR /app

COPY package.json  pnpm-lock.yaml ./

RUN pnpm i --frozen-lockfile

COPY . .

RUN npx prisma generate

RUN pnpm build

RUN pnpm prune --prod

FROM node:22-alpine

WORKDIR /app

COPY --from=builder /app/package.json ./package.json
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/prisma/schema.prisma ./prisma/schema.prisma

CMD ["node", "dist/main.js"]