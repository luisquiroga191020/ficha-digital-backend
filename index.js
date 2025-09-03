// index.js (Versión completa con flujo de estados de afiliación)

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
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (token == null) return res.sendStatus(401);
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

const authorize = (allowedRoles) => {
  return (req, res, next) => {
    const userRole = req.user.role;
    if (allowedRoles.includes(userRole)) {
      next();
    } else {
      res
        .status(403)
        .json({
          message: "Acceso denegado: no tienes los permisos necesarios.",
        });
    }
  };
};

// 5. RUTAS (ENDPOINTS) DE LA API
// -----------------------------------------------------------------------------

// --- Autenticación ---
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
    const token = jwt.sign(
      {
        userId: user.id,
        name: user.full_name,
        email: user.email,
        codigo: user.codigo,
        role: user.role,
      },
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

// --- GESTIÓN DE USUARIOS (SOLO ADMIN) ---
app.get(
  "/api/users",
  authenticateToken,
  authorize(["ADMINISTRADOR"]),
  async (req, res) => {
    try {
      const result = await pool.query(
        "SELECT id, full_name, email, codigo, role FROM users ORDER BY full_name"
      );
      res.json(result.rows);
    } catch (error) {
      res.status(500).json({ message: "Error al obtener usuarios." });
    }
  }
);

app.post(
  "/api/users",
  authenticateToken,
  authorize(["ADMINISTRADOR"]),
  async (req, res) => {
    const { full_name, email, password, codigo, role } = req.body;
    if (!full_name || !email || !password || !role) {
      return res
        .status(400)
        .json({ message: "Todos los campos son obligatorios." });
    }
    try {
      const salt = await bcrypt.genSalt(10);
      const password_hash = await bcrypt.hash(password, salt);
      const newUser = await pool.query(
        "INSERT INTO users (full_name, email, password_hash, codigo, role) VALUES ($1, $2, $3, $4, $5) RETURNING id, full_name, email, codigo, role",
        [full_name, email.toLowerCase(), password_hash, codigo, role]
      );
      res.status(201).json(newUser.rows[0]);
    } catch (error) {
      if (error.code === "23505") {
        return res
          .status(409)
          .json({ message: "El correo electrónico o el código ya existen." });
      }
      res.status(500).json({ message: "Error al crear el usuario." });
    }
  }
);

app.put(
  "/api/users/:id",
  authenticateToken,
  authorize(["ADMINISTRADOR"]),
  async (req, res) => {
    const { id } = req.params;
    const { full_name, email, codigo, role } = req.body;
    try {
      const updatedUser = await pool.query(
        "UPDATE users SET full_name = $1, email = $2, codigo = $3, role = $4 WHERE id = $5 RETURNING id, full_name, email, codigo, role",
        [full_name, email.toLowerCase(), codigo, role, id]
      );
      if (updatedUser.rows.length === 0) {
        return res.status(404).json({ message: "Usuario no encontrado." });
      }
      res.json(updatedUser.rows[0]);
    } catch (error) {
      res.status(500).json({ message: "Error al actualizar el usuario." });
    }
  }
);

app.delete(
  "/api/users/:id",
  authenticateToken,
  authorize(["ADMINISTRADOR"]),
  async (req, res) => {
    const { id } = req.params;
    try {
      await pool.query("DELETE FROM users WHERE id = $1", [id]);
      res.status(204).send();
    } catch (error) {
      res.status(500).json({ message: "Error al eliminar el usuario." });
    }
  }
);

// --- GESTIÓN DE AFILIACIONES ---
app.post(
  "/api/submit-ficha",
  authenticateToken,
  authorize(["VENDEDOR", "SUPERVISOR", "ADMINISTRADOR"]),
  async (req, res) => {
    const { formData, latitud, longitud } = req.body;
    const userId = req.user.userId;
    const titular_nombre = `${formData.apellidoTitular || ""}, ${
      formData.nombreTitular || ""
    }`;

    try {
      // No se necesita cambiar, la DB asigna el status 'Presentado' por defecto
      await pool.query(
        "INSERT INTO affiliations (user_id, form_data, titular_nombre, titular_dni, plan, latitud, longitud) VALUES ($1, $2, $3, $4, $5, $6, $7)",
        [
          userId,
          formData,
          titular_nombre,
          formData.dniTitular,
          formData.plan,
          latitud,
          longitud,
        ]
      );
      res.status(201).json({ message: "Ficha guardada correctamente." });
    } catch (error) {
      console.error("Error al guardar la ficha:", error);
      res.status(500).json({ message: "Error al guardar la ficha." });
    }
  }
);

app.get("/api/affiliations", authenticateToken, async (req, res) => {
  const { userId, role } = req.user;
  try {
    // MODIFICADO: Se añade a.status a la selección
    let query = `
      SELECT
        a.id,
        a.titular_nombre,
        a.titular_dni,
        a.plan,
        a.form_data ->> 'total' as total,
        u.full_name as vendor_name,
        a.fecha_creacion,
        a.status
      FROM affiliations a
      JOIN users u ON a.user_id = u.id
    `;
    const params = [];

    if (role === "VENDEDOR") {
      query += " WHERE a.user_id = $1";
      params.push(userId);
    }

    query += " ORDER BY a.fecha_creacion DESC";

    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (error) {
    console.error("Error al obtener afiliaciones:", error);
    res.status(500).json({ message: "Error al obtener afiliaciones." });
  }
});

app.get("/api/affiliations/:id", authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { userId, role } = req.user;
  try {
    let query = "SELECT * FROM affiliations WHERE id = $1";
    const params = [id];

    if (role === "VENDEDOR") {
      query += " AND user_id = $2";
      params.push(userId);
    }

    const result = await pool.query(query, params);

    if (result.rows.length === 0) {
      return res
        .status(404)
        .json({
          message: "Afiliación no encontrada o no tienes permiso para verla.",
        });
    }

    const affiliationDetails = {
    ...result.rows[0].form_data,
    id: result.rows[0].id, 
    latitud: result.rows[0].latitud,
    longitud: result.rows[0].longitud,
    status: result.rows[0].status,
};

    res.json(affiliationDetails);
  } catch (error) {
    console.error("Error al obtener detalle de la afiliación:", error);
    res.status(500).json({ message: "Error interno del servidor." });
  }
});

// NUEVO: ENDPOINT PARA ACTUALIZAR EL ESTADO DE UNA AFILIACIÓN
app.put('/api/affiliations/:id/status', authenticateToken, authorize(['SUPERVISOR', 'ADMINISTRADOR']), async (req, res) => {
    const { id } = req.params;
    const { newStatus } = req.body;

    if (!['Aprobado', 'Rechazado'].includes(newStatus)) {
        return res.status(400).json({ message: 'Estado no válido.' });
    }

    try {
        const current = await pool.query('SELECT status FROM affiliations WHERE id = $1', [id]);
        if (current.rows.length === 0) {
            return res.status(404).json({ message: 'Afiliación no encontrada.' });
        }
        if (current.rows[0].status !== 'Presentado') {
            return res.status(409).json({ message: `Esta afiliación ya está en estado '${current.rows[0].status}' y no se puede cambiar.` });
        }

        const result = await pool.query(
            'UPDATE affiliations SET status = $1 WHERE id = $2 RETURNING status',
            [newStatus, id]
        );
        res.json({ newStatus: result.rows[0].status });

    } catch (error) {
        console.error('Error al actualizar estado:', error);
        res.status(500).json({ message: 'Error interno del servidor.' });
    }
});

// --- Datos para Selectores (Planes y Empresas) ---
app.get("/api/planes", authenticateToken, async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM planes ORDER BY label");
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ message: "Error interno del servidor." });
  }
});

app.get("/api/empresas", authenticateToken, async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM empresas ORDER BY label");
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ message: "Error interno del servidor." });
  }
});

// 6. INICIAR EL SERVIDOR
app.listen(PORT, () => {
  console.log(`🚀 Servidor backend corriendo en el puerto ${PORT}`);
});