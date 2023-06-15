# FROM node:16-alpine3.16

# COPY ./hello-cage/index.js /index.js
# COPY ./hello-cage/package.json /package.json
# COPY ./hello-cage/package-lock.json /package-lock.json

# EXPOSE 8008

# RUN npm i

# ENTRYPOINT ["node", "/index.js"]


# FROM node:18-alpine AS builder

# WORKDIR /usr/app
# COPY package.json .
# COPY tsconfig.json .
# COPY yarn.lock .
# RUN yarn install

# # set up source
# COPY ./src ./src
# RUN yarn run build

FROM node:18-slim

EXPOSE 3000
# WORKDIR /usr/app
# RUN chown node:node .
# COPY package.json .
# COPY yarn.lock .
# RUN yarn install --production
# COPY --from=builder /usr/app/dist ./dist

# USER node

CMD yarn run start