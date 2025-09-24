# Usar la imagen oficial de Node.js 20-slim como base
FROM node:20-slim

# Instalar dependencias del sistema y herramientas necesarias
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    gnupg \
    # Limpiar caché al final
    && rm -rf /var/lib/apt/lists/*

# =================================================================================
# ===== NUEVO MÉTODO SEGURO PARA AÑADIR EL REPOSITORIO DE GOOGLE CHROME =====
# =================================================================================
RUN curl -sS https://dl.google.com/linux/linux_signing_key.pub | gpg --dearmor -o /usr/share/keyrings/google-chrome-archive-keyring.gpg \
    && echo "deb [arch=amd64 signed-by=/usr/share/keyrings/google-chrome-archive-keyring.gpg] http://dl.google.com/linux/chrome/deb/ stable main" > /etc/apt/sources.list.d/google-chrome.list
# =================================================================================

# Instalar Google Chrome y las fuentes, luego limpiar
RUN apt-get update \
    && apt-get install -y google-chrome-stable fonts-ipafont-gothic fonts-wqy-zenhei fonts-thai-tlwg fonts-kacst fonts-freefont-ttf libxss1 \
    --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

# Establecer el directorio de trabajo
WORKDIR /usr/src/app

# Copiar los archivos de dependencias
COPY package*.json ./

# Instalar las dependencias del proyecto de Node.js
# Usamos PUPPETEER_SKIP_CHROMIUM_DOWNLOAD=true para evitar que npm descargue Chrome,
# ya que lo estamos instalando manualmente con apt-get.
ENV PUPPETEER_SKIP_CHROMIUM_DOWNLOAD=true
RUN npm install

# Copiar el resto del código
COPY . .

# Exponer el puerto
EXPOSE 3001

# Comando para iniciar la aplicación
CMD [ "node", "index.js" ]