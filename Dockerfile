# Usar una imagen oficial de Node.js. La versión 20 es una buena elección estable (LTS).
FROM node:20-slim

# Instalar las dependencias que Puppeteer necesita en el sistema operativo Debian
# (Esta es la parte que soluciona el error)
RUN apt-get update \
    && apt-get install -yq libgconf-2-4 libasound2 libatk1.0-0 libc6 libcairo2 libcups2 libdbus-1-3 \
    libexpat1 libfontconfig1 libgcc1 libgdk-pixbuf2.0-0 libglib2.0-0 libgtk-3-0 libnspr4 \
    libpango-1.0-0 libpangocairo-1.0-0 libstdc++6 libx11-6 libx11-xcb1 libxcb1 libxcomposite1 \
    libxcursor1 libxdamage1 libxext6 libxfixes3 libxi6 libxrandr2 libxrender1 libxss1 libxtst6 \
    ca-certificates fonts-liberation libappindicator1 libnss3 lsb-release xdg-utils wget

# Establecer el directorio de trabajo dentro del contenedor
WORKDIR /usr/src/app

# Copiar los archivos de dependencias
COPY package.json ./
COPY package-lock.json ./

# Instalar las dependencias del proyecto, incluyendo Puppeteer.
# Puppeteer detectará las librerías del sistema y no necesitará descargar su propia versión de Chrome.
RUN npm install --ignore-scripts

# Copiar el resto del código de la aplicación
COPY . .

# Exponer el puerto que tu aplicación usa (si es diferente, cámbialo)
EXPOSE 3001

# El comando para iniciar la aplicación
CMD [ "node", "index.js" ]