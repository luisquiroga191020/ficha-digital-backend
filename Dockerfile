# Usar una imagen base de Node.js delgada para mantener el tamaño bajo
FROM node:20-slim

# Instalar dependencias del sistema operativo necesarias para Chrome
# y también 'ca-certificates' para conexiones HTTPS
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
    ca-certificates \
    fonts-liberation \
    libasound2 \
    libatk-bridge2.0-0 \
    libatk1.0-0 \
    libcairo2 \
    libcups2 \
    libdbus-1-3 \
    libexpat1 \
    libfontconfig1 \
    libgbm1 \
    libgcc1 \
    libgconf-2-4 \
    libgdk-pixbuf2.0-0 \
    libglib2.0-0 \
    libgtk-3-0 \
    libnspr4 \
    libnss3 \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libstdc++6 \
    libx11-6 \
    libx11-xcb1 \
    libxcb1 \
    libxcomposite1 \
    libxcursor1 \
    libxdamage1 \
    libxext6 \
    libxfixes3 \
    libxi6 \
    libxrandr2 \
    libxrender1 \
    libxss1 \
    libxtst6 \
    libxtst6 \
    lsb-release \
    wget \
    xdg-utils \
    --fix-missing

WORKDIR /usr/src/app

COPY package*.json ./

# Instalar dependencias. Usamos --no-optional para saltar
# la descarga de Chrome que haría puppeteer si estuviera como dependencia.
RUN npm install --no-optional

COPY . .

# Comando para iniciar la aplicación
CMD [ "node", "index.js" ]