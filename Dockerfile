FROM oven/bun:1

WORKDIR /app

COPY src ./
COPY drizzle ./
COPY drizzle.config.ts ./

EXPOSE 3000

CMD [ "bun", "dev" ]