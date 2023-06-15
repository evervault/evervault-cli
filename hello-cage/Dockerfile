FROM node:16-alpine3.16

COPY ./hello-cage/index.js /index.js
COPY ./hello-cage/package.json /package.json
COPY ./hello-cage/package-lock.json /package-lock.json

RUN npm i

ENTRYPOINT ["node", "/index.js"]