// index.js (Versión completa con sistema de roles)

// 1. IMPORTAR LIBRERÍAS
// -----------------------------------------------------------------------------
require("dotenv").config();
const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

// 2. CONFIGURACIÓN INICIAL
// -----------------------------------------------------------------------------
const app = express();
const PORT = process.env.PORT || 3001;
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

// 3. MIDDLEWARES
// -----------------------------------------------------------------------------
const corsOptions = {
  origin: "*",
  methods: ["GET", "POST", "PUT", "DELETE"],
  allowedHeaders: ["Content-Type", "Authorization"],
};
app.use(cors(corsOptions));
app.use(express.json({ limit: "5mb" }));

// 4. LÓGICA DE AUTENTICACIÓN Y AUTORIZACIÓN
// -----------------------------------------------------------------------------

// MIDDLEWARE DE AUTENTICACIÓN (Verifica si el token es válido)
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (token == null) return res.sendStatus(401); // No hay token
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403); // Token inválido
    req.user = user; // Guardamos los datos del token (incluyendo el rol)
    next();
  });
};

// MIDDLEWARE DE AUTORIZACIÓN (Verifica si el rol es permitido)
const authorize = (allowedRoles) => {
  return (req, res, next) => {
    const userRole = req.user.role;
    if (allowedRoles.includes(userRole)) {
      next(); // El rol está permitido, continuar
    } else {
      res
        .status(403)
        .json({
          message: "Acceso denegado: no tienes los permisos necesarios.",
        }); // El rol no tiene permiso
    }
  };
};

// 5. RUTAS (ENDPOINTS) DE LA API
// -----------------------------------------------------------------------------

// RUTA DE LOGIN (Pública)
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res
      .status(400)
      .json({ message: "El correo y la contraseña son obligatorios." });
  }
  try {
    const result = await pool.query("SELECT * FROM users WHERE email = $1", [
      email.toLowerCase(),
    ]);
    const user = result.rows[0];
    if (!user) {
      return res.status(401).json({ message: "Credenciales inválidas." });
    }
    const isPasswordValid = await bcrypt.compare(password, user.password_hash);
    if (!isPasswordValid) {
      return res.status(401).json({ message: "Credenciales inválidas." });
    }

    // Incluimos los nuevos datos en el token y la respuesta
    // Versión Corregida del token
    const token = jwt.sign(
      {
        userId: user.id,
        name: user.full_name,
        email: user.email,
        codigo: user.codigo,
        role: user.role,
      }, // <-- AÑADIMOS EL NOMBRE AQUÍ
      process.env.JWT_SECRET,
      { expiresIn: "8h" }
    );
    res.json({
      token,
      user: {
        name: user.full_name,
        email: user.email,
        codigo: user.codigo,
        role: user.role,
      },
    });
  } catch (error) {
    console.error("Error en el login:", error);
    res.status(500).json({ message: "Error interno del servidor." });
  }
});

// RUTA PARA ENVIAR LA FICHA
// Permitida para Vendedores, Supervisores y Administradores
app.post(
  "/api/submit-ficha",
  authenticateToken,
  authorize(["VENDEDOR", "SUPERVISOR", "ADMINISTRADOR"]),
  async (req, res) => {
    const formData = req.body;
    const userId = req.user.userId;
    try {
      await pool.query(
        "INSERT INTO affiliations (user_id, form_data) VALUES ($1, $2)",
        [userId, formData]
      );
      res.status(201).json({ message: "Ficha guardada correctamente." });
    } catch (error) {
      console.error("Error al guardar la ficha:", error);
      res
        .status(500)
        .json({ message: "Error al guardar la ficha en la base de datos." });
    }
  }
);

// RUTA PARA OBTENER PLANES
// Todos los roles logueados pueden verlos
app.get("/api/planes", authenticateToken, async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM planes ORDER BY label");
    res.json(result.rows);
  } catch (error) {
    console.error("Error al obtener planes:", error);
    res.status(500).json({ message: "Error interno del servidor." });
  }
});

// RUTA PARA OBTENER EMPRESAS
// Todos los roles logueados pueden verlas
app.get("/api/empresas", authenticateToken, async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM empresas ORDER BY label");
    res.json(result.rows);
  } catch (error) {
    console.error("Error al obtener empresas:", error);
    res.status(500).json({ message: "Error interno del servidor." });
  }
});

// RUTA PARA GESTIONAR USUARIOS
// Solo los Administradores pueden acceder
app.get(
  "/api/users",
  authenticateToken,
  authorize(["ADMINISTRADOR"]),
  async (req, res) => {
    try {
      // No devolvemos el password_hash por seguridad
      const result = await pool.query(
        "SELECT id, full_name, email, codigo, role FROM users ORDER BY full_name"
      );
      res.json(result.rows);
    } catch (error) {
      console.error("Error al obtener usuarios:", error);
      res.status(500).json({ message: "Error interno del servidor." });
    }
  }
);

// 6. INICIAR EL SERVIDOR
// -----------------------------------------------------------------------------
app.listen(PORT, () => {
  console.log(`🚀 Servidor backend corriendo en el puerto ${PORT}`);
});
