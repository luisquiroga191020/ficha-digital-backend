# Usar la imagen oficial de Node.js 20-slim como base
FROM node:20-slim

# Instalar wget y ca-certificates, herramientas necesarias para descargar Chrome
RUN apt-get update && apt-get install -y wget ca-certificates

# =================================================================================
# ===== ESTE ES EL BLOQUE CLAVE: DESCARGAR E INSTALAR GOOGLE CHROME OFICIAL =====
# =================================================================================
# Añadir el repositorio de Google Chrome a las fuentes de software del sistema
RUN wget -q -O - https://dl.google.com/linux/linux_signing_key.pub | apt-key add - \
    && sh -c 'echo "deb [arch=amd64] http://dl.google.com/linux/chrome/deb/ stable main" >> /etc/apt/sources.list.d/google.list'

# Actualizar la lista de paquetes e instalar Chrome Stable y las fuentes necesarias
RUN apt-get update \
    && apt-get install -y google-chrome-stable fonts-ipafont-gothic fonts-wqy-zenhei fonts-thai-tlwg fonts-kacst fonts-freefont-ttf libxss1 \
    --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*
# =================================================================================

# Establecer el directorio de trabajo
WORKDIR /usr/src/app

# Copiar los archivos de dependencias
COPY package*.json ./

# Instalar las dependencias de Node.js
RUN npm install

# Copiar el resto del código de la aplicación
COPY . .

# Exponer el puerto
EXPOSE 3001

# El comando para iniciar la aplicación
CMD [ "node", "index.js" ]