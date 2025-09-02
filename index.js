// index.js

// 1. IMPORTAR LIBRERÍAS
// -----------------------------------------------------------------------------
require('dotenv').config(); // Carga las variables del archivo .env
const express = require('express');
const cors = require('cors'); // Para la política de orígenes cruzados (CORS)
const { Pool } = require('pg'); // Para conectar con PostgreSQL
const bcrypt = require('bcryptjs'); // Para encriptar contraseñas
const jwt = require('jsonwebtoken'); // Para los tokens de autenticación

// 2. CONFIGURACIÓN INICIAL
// -----------------------------------------------------------------------------
const app = express();
const PORT = process.env.PORT || 3001; // Render usará process.env.PORT

// Crear una instancia de conexión a la base de datos
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false // Necesario para conexiones seguras a Neon/Render
  }
});

// 3. MIDDLEWARES
// -----------------------------------------------------------------------------

// --- SOLUCIÓN AL ERROR CORS ---
// Configuración explícita de CORS para permitir peticiones desde cualquier origen
const corsOptions = {
  origin: '*', // Permite peticiones de CUALQUIER origen.
  methods: ['GET', 'POST', 'PUT', 'DELETE'], // Métodos HTTP permitidos
  allowedHeaders: ['Content-Type', 'Authorization'], // Encabezados permitidos en las peticiones
};
app.use(cors(corsOptions));
// --- FIN DE LA SOLUCIÓN ---

app.use(express.json({ limit: '5mb' })); // Permite al servidor entender JSON y aumenta el límite para la firma

// 4. RUTAS (ENDPOINTS) DE LA API
// -----------------------------------------------------------------------------

// RUTA DE LOGIN (Pública)
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: 'El correo y la contraseña son obligatorios.' });
  }

  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email.toLowerCase()]);
    const user = result.rows[0];

    if (!user) {
      return res.status(401).json({ message: 'Credenciales inválidas.' });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password_hash);
    if (!isPasswordValid) {
      return res.status(401).json({ message: 'Credenciales inválidas.' });
    }

    const token = jwt.sign(
      { userId: user.id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: '8h' }
    );

    res.json({
      token,
      user: {
        name: user.full_name,
        email: user.email
      }
    });

  } catch (error) {
    console.error('Error en el login:', error);
    res.status(500).json({ message: 'Error interno del servidor.' });
  }
});

// MIDDLEWARE DE AUTENTICACIÓN (Verifica el token en rutas protegidas)
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Formato: "Bearer TOKEN"

  if (token == null) {
    return res.sendStatus(401); // No hay token, no autorizado
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      console.error('Error de token:', err.message);
      return res.sendStatus(403); // Token inválido o expirado
    }
    req.user = user; // Guardamos los datos del usuario del token en la request
    next(); // Pasa al siguiente paso (la lógica de la ruta)
  });
};

// RUTA PARA ENVIAR LA FICHA (Protegida)
app.post('/api/submit-ficha', authenticateToken, async (req, res) => {
  const formData = req.body;
  const userId = req.user.userId; // Obtenemos el ID del vendedor desde el token

  try {
    await pool.query(
      'INSERT INTO affiliations (user_id, form_data) VALUES ($1, $2)',
      [userId, formData]
    );
    res.status(201).json({ message: 'Ficha guardada correctamente.' });

  } catch (error) {
    console.error('Error al guardar la ficha:', error);
    res.status(500).json({ message: 'Error al guardar la ficha en la base de datos.' });
  }
});

// 5. INICIAR EL SERVIDOR
// -----------------------------------------------------------------------------
app.listen(PORT, () => {
  console.log(`🚀 Servidor backend corriendo en el puerto ${PORT}`);
});