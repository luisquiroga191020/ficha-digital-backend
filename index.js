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
      res.status(403).json({
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
    // Unimos la tabla de afiliaciones con la de usuarios para obtener el nombre de quien cambió el estado
    let query = `
            SELECT a.*, u.full_name as status_change_user_name 
            FROM affiliations a
            LEFT JOIN users u ON a.status_change_user_id = u.id
            WHERE a.id = $1
        `;
    const params = [id];

    if (role === "VENDEDOR") {
      query += " AND a.user_id = $2";
      params.push(userId);
    }

    const result = await pool.query(query, params);

    if (result.rows.length === 0) {
      return res
        .status(404)
        .json({ message: "Afiliación no encontrada o sin permiso." });
    }

    const affiliationDetails = {
      ...result.rows[0].form_data,
      id: result.rows[0].id,
      latitud: result.rows[0].latitud,
      longitud: result.rows[0].longitud,
      status: result.rows[0].status,
      // Añadimos los nuevos campos a la respuesta
      statusChangeTimestamp: result.rows[0].status_change_timestamp,
      statusChangeUserName: result.rows[0].status_change_user_name,
      rechazoMotivo: result.rows[0].rechazo_motivo,
    };

    res.json(affiliationDetails);
  } catch (error) {
    console.error("Error al obtener detalle:", error);
    res.status(500).json({ message: "Error interno del servidor." });
  }
});

// Dentro de 5. RUTAS (ENDPOINTS) DE LA API

app.put(
  "/api/affiliations/:id/status",
  authenticateToken,
  authorize(["SUPERVISOR", "ADMINISTRADOR"]),
  async (req, res) => {
    const { id } = req.params;
    const { newStatus, motivo } = req.body; // Aceptamos el nuevo campo 'motivo'
    const changingUserId = req.user.userId; // Obtenemos el ID del usuario que realiza la acción

    if (!["Aprobado", "Rechazado"].includes(newStatus)) {
      return res.status(400).json({ message: "Estado no válido." });
    }
    // Si el estado es 'Rechazado', el motivo es obligatorio
    if (newStatus === "Rechazado" && (!motivo || motivo.trim() === "")) {
      return res
        .status(400)
        .json({ message: "El motivo del rechazo es obligatorio." });
    }

    try {
      const current = await pool.query(
        "SELECT status FROM affiliations WHERE id = $1",
        [id]
      );
      if (current.rows.length === 0) {
        return res.status(404).json({ message: "Afiliación no encontrada." });
      }
      if (current.rows[0].status !== "Presentado") {
        return res.status(409).json({
          message: `Esta afiliación ya está en estado '${current.rows[0].status}' y no se puede cambiar.`,
        });
      }

      // Actualizamos la tabla con todos los nuevos datos
      const result = await pool.query(
        `UPDATE affiliations 
             SET status = $1, 
                 status_change_user_id = $2, 
                 status_change_timestamp = NOW(), 
                 rechazo_motivo = $3 
             WHERE id = $4 
             RETURNING status, status_change_timestamp, rechazo_motivo`,
        [
          newStatus,
          changingUserId,
          newStatus === "Rechazado" ? motivo : null,
          id,
        ]
      );

      res.json({
        newStatus: result.rows[0].status,
        timestamp: result.rows[0].status_change_timestamp,
        motivo: result.rows[0].rechazo_motivo,
      });
    } catch (error) {
      console.error("Error al actualizar estado:", error);
      res.status(500).json({ message: "Error interno del servidor." });
    }
  }
);

// --- Datos para Selectores (Planes y Empresas) ---
// ==========================================================
// ABM PARA LA TABLA DE PLANES (SOLO ADMIN)
// ==========================================================
app.post(
  "/api/planes",
  authenticateToken,
  authorize(["ADMINISTRADOR"]),
  async (req, res) => {
    const { label, value, tipo } = req.body;
    if (!label || !value || !tipo) {
      return res
        .status(400)
        .json({ message: "Los campos label, value y tipo son obligatorios." });
    }
    try {
      const newPlan = await pool.query(
        "INSERT INTO planes (label, value, tipo) VALUES ($1, $2, $3) RETURNING *",
        [label, value, tipo]
      );
      res.status(201).json(newPlan.rows[0]);
    } catch (error) {
      if (error.code === "23505") {
        return res
          .status(409)
          .json({ message: 'El "value" del plan ya existe.' });
      }
      res.status(500).json({ message: "Error al crear el plan." });
    }
  }
);

app.put(
  "/api/planes/:id",
  authenticateToken,
  authorize(["ADMINISTRADOR"]),
  async (req, res) => {
    const { id } = req.params;
    const { label, value, tipo } = req.body;
    if (!label || !value || !tipo) {
      return res
        .status(400)
        .json({ message: "Todos los campos son obligatorios." });
    }
    try {
      const updatedPlan = await pool.query(
        "UPDATE planes SET label = $1, value = $2, tipo = $3 WHERE id = $4 RETURNING *",
        [label, value, tipo, id]
      );
      if (updatedPlan.rows.length === 0) {
        return res.status(404).json({ message: "Plan no encontrado." });
      }
      res.json(updatedPlan.rows[0]);
    } catch (error) {
      res.status(500).json({ message: "Error al actualizar el plan." });
    }
  }
);

app.delete(
  "/api/planes/:id",
  authenticateToken,
  authorize(["ADMINISTRADOR"]),
  async (req, res) => {
    const { id } = req.params;
    try {
      await pool.query("DELETE FROM planes WHERE id = $1", [id]);
      res.status(204).send();
    } catch (error) {
      if (error.code === "23503") {
        // Error de foreign key violation
        return res
          .status(409)
          .json({
            message:
              "No se puede eliminar el plan porque está siendo utilizado por una o más afiliaciones.",
          });
      }
      res.status(500).json({ message: "Error al eliminar el plan." });
    }
  }
);

// ==========================================================
// ABM PARA LA TABLA DE EMPRESAS (SOLO ADMIN)
// ==========================================================
app.post(
  "/api/empresas",
  authenticateToken,
  authorize(["ADMINISTRADOR"]),
  async (req, res) => {
    const { label, value } = req.body;
    if (!label || !value) {
      return res
        .status(400)
        .json({ message: "Los campos label y value son obligatorios." });
    }
    try {
      const newEmpresa = await pool.query(
        "INSERT INTO empresas (label, value) VALUES ($1, $2) RETURNING *",
        [label, value]
      );
      res.status(201).json(newEmpresa.rows[0]);
    } catch (error) {
      if (error.code === "23505") {
        return res
          .status(409)
          .json({ message: 'El "value" de la empresa ya existe.' });
      }
      res.status(500).json({ message: "Error al crear la empresa." });
    }
  }
);

app.put(
  "/api/empresas/:id",
  authenticateToken,
  authorize(["ADMINISTRADOR"]),
  async (req, res) => {
    const { id } = req.params;
    const { label, value } = req.body;
    if (!label || !value) {
      return res
        .status(400)
        .json({ message: "Todos los campos son obligatorios." });
    }
    try {
      const updatedEmpresa = await pool.query(
        "UPDATE empresas SET label = $1, value = $2 WHERE id = $3 RETURNING *",
        [label, value, id]
      );
      if (updatedEmpresa.rows.length === 0) {
        return res.status(404).json({ message: "Empresa no encontrada." });
      }
      res.json(updatedEmpresa.rows[0]);
    } catch (error) {
      res.status(500).json({ message: "Error al actualizar la empresa." });
    }
  }
);

app.delete(
  "/api/empresas/:id",
  authenticateToken,
  authorize(["ADMINISTRADOR"]),
  async (req, res) => {
    const { id } = req.params;
    // Aquí la validación debe ser manual porque no tenemos foreign key
    try {
      const usage = await pool.query(
        "SELECT 1 FROM affiliations WHERE form_data ->> 'empresa' = (SELECT value FROM empresas WHERE id = $1) LIMIT 1",
        [id]
      );
      if (usage.rows.length > 0) {
        return res
          .status(409)
          .json({
            message: "No se puede eliminar la empresa porque está en uso.",
          });
      }
      await pool.query("DELETE FROM empresas WHERE id = $1", [id]);
      res.status(204).send();
    } catch (error) {
      res.status(500).json({ message: "Error al eliminar la empresa." });
    }
  }
);

// 6. INICIAR EL SERVIDOR
app.listen(PORT, () => {
  console.log(`🚀 Servidor backend corriendo en el puerto ${PORT}`);
});
