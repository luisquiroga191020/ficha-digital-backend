// 1. IMPORTAR LIBRERÍAS
// -----------------------------------------------------------------------------
require("dotenv").config();
const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cloudinary = require("cloudinary").v2;
const multer = require("multer");
const puppeteer = require("puppeteer");
const handlebars = require("handlebars");
const fs = require("fs").promises;
const path = require("path");

// 2. CONFIGURACIÓN INICIAL
// -----------------------------------------------------------------------------
const app = express();
const PORT = process.env.PORT || 3001;
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
  secure: true,
});

const storage = multer.memoryStorage();
const upload = multer({ storage: storage });
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

// 3. MIDDLEWARES
// -----------------------------------------------------------------------------
app.use(
  cors({
    origin: "*",
    methods: "GET,HEAD,PUT,PATCH,POST,DELETE",
    allowedHeaders: "Content-Type,Authorization",
    exposedHeaders: "Content-Disposition",
    preflightContinue: false,
    optionsSuccessStatus: 204,
  })
);

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

// --- ABM de Circulares ---
app.get(
  "/api/circulares",
  authenticateToken,
  authorize(["SUPERVISOR", "ADMINISTRADOR"]),
  async (req, res) => {
    try {
      const result = await pool.query(
        "SELECT c.*, u.full_name as creado_por_nombre FROM circulares c JOIN users u ON c.creado_por_id = u.id ORDER BY c.fecha_creacion DESC"
      );
      res.json(result.rows);
    } catch (error) {
      res.status(500).json({ message: "Error al obtener circulares." });
    }
  }
);

app.post(
  "/api/circulares",
  authenticateToken,
  authorize(["SUPERVISOR", "ADMINISTRADOR"]),
  async (req, res) => {
    const { titulo, contenido } = req.body;
    const userId = req.user.userId;
    if (!titulo || !contenido)
      return res
        .status(400)
        .json({ message: "El título y el contenido son obligatorios." });
    try {
      const newCircular = await pool.query(
        "INSERT INTO circulares (titulo, contenido, creado_por_id) VALUES ($1, $2, $3) RETURNING *",
        [titulo, contenido, userId]
      );
      res.status(201).json(newCircular.rows[0]);
    } catch (error) {
      res.status(500).json({ message: "Error al crear la circular." });
    }
  }
);

app.put(
  "/api/circulares/:id",
  authenticateToken,
  authorize(["SUPERVISOR", "ADMINISTRADOR"]),
  async (req, res) => {
    const { id } = req.params;
    const { titulo, contenido, activa } = req.body;
    try {
      const updatedCircular = await pool.query(
        "UPDATE circulares SET titulo = $1, contenido = $2, activa = $3 WHERE id = $4 RETURNING *",
        [titulo, contenido, activa, id]
      );
      res.json(updatedCircular.rows[0]);
    } catch (error) {
      res.status(500).json({ message: "Error al actualizar la circular." });
    }
  }
);

// --- Lógica para Vendedores ---
app.get("/api/mis-circulares", authenticateToken, async (req, res) => {
  const userId = req.user.userId;
  try {
    const result = await pool.query(
      `
            SELECT c.*, u.full_name as creado_por_nombre, cf.fecha_firma 
            FROM circulares c
            JOIN users u ON c.creado_por_id = u.id
            LEFT JOIN circulares_firmas cf ON c.id = cf.circular_id AND cf.usuario_id = $1
            WHERE c.activa = TRUE
            ORDER BY c.fecha_creacion DESC
        `,
      [userId]
    );
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ message: "Error al obtener tus circulares." });
  }
});

app.post("/api/circulares/:id/firmar", authenticateToken, async (req, res) => {
  const { id } = req.params;
  const userId = req.user.userId;
  try {
    await pool.query(
      "INSERT INTO circulares_firmas (circular_id, usuario_id) VALUES ($1, $2)",
      [id, userId]
    );
    res.status(201).json({ message: "Circular firmada con éxito." });
  } catch (error) {
    if (error.code === "23505") {
      return res.status(409).json({ message: "Ya has firmado esta circular." });
    }
    res.status(500).json({ message: "Error al firmar la circular." });
  }
});

// --- Lógica para Supervisores/Admins ---
app.get(
  "/api/circulares/:id/firmas",
  authenticateToken,
  authorize(["SUPERVISOR", "ADMINISTRADOR"]),
  async (req, res) => {
    const { id } = req.params;
    try {
      const quienesFirmaron = await pool.query(
        `
            SELECT u.full_name, u.codigo, cf.fecha_firma
            FROM circulares_firmas cf
            JOIN users u ON cf.usuario_id = u.id
            WHERE cf.circular_id = $1
            ORDER BY cf.fecha_firma
        `,
        [id]
      );

      const todosLosVendedores = await pool.query(
        "SELECT id, full_name, codigo FROM users WHERE role = 'VENDEDOR'"
      );

      const firmaronIds = quienesFirmaron.rows.map((u) => u.id);
      const faltanFirmar = todosLosVendedores.rows.filter(
        (vendedor) => !firmaronIds.includes(vendedor.id)
      );

      res.json({
        firmaron: quienesFirmaron.rows,
        faltan: faltanFirmar,
      });
    } catch (error) {
      res
        .status(500)
        .json({ message: "Error al obtener el estado de las firmas." });
    }
  }
);

// --- GESTIÓN DE USUARIOS ---
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
    const { latitudDomicilio, longitudDomicilio } = formData;
    const userId = req.user.userId;
    const titular_nombre = `${formData.apellidoTitular || ""}, ${
      formData.nombreTitular || ""
    }`;

    try {
      const result = await pool.query(
        `INSERT INTO affiliations (
            user_id, form_data, titular_nombre, titular_dni, plan, 
            latitud, longitud, 
            domicilio_latitud, domicilio_longitud
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING *`,
        [
          userId,
          formData,
          titular_nombre,
          formData.dniTitular,
          formData.plan,
          latitud,
          longitud,
          latitudDomicilio,
          longitudDomicilio,
        ]
      );

      res.status(201).json(result.rows[0]);
    } catch (error) {
      console.error("Error al guardar la ficha:", error);
      res.status(500).json({ message: "Error al guardar la ficha." });
    }
  }
);

app.get("/api/affiliations", authenticateToken, async (req, res) => {
  const { userId, role } = req.user;

  const { page = 1, rowsPerPage = 20, filter, sortBy, descending } = req.query;

  try {
    let whereClauses = [];
    const params = [];
    let paramCounter = 1;

    if (role === "VENDEDOR") {
      whereClauses.push(`a.user_id = $${paramCounter++}`);
      params.push(userId);
    }

    if (filter) {
      whereClauses.push(
        `(a.titular_nombre ILIKE $${paramCounter} OR a.titular_dni ILIKE $${paramCounter} OR a.plan ILIKE $${paramCounter} OR u.full_name ILIKE $${paramCounter})`
      );
      params.push(`%${filter}%`);
      paramCounter++;
    }

    const whereCondition =
      whereClauses.length > 0 ? `WHERE ${whereClauses.join(" AND ")}` : "";

    const totalResult = await pool.query(
      `SELECT COUNT(*) FROM affiliations a JOIN users u ON a.user_id = u.id ${whereCondition}`,
      params
    );
    const totalRows = parseInt(totalResult.rows[0].count, 10);

    const offset = (page - 1) * rowsPerPage;
    const limit = rowsPerPage === "0" ? null : rowsPerPage;

    const orderByMap = {
      titular_nombre: "a.titular_nombre",
      plan: "a.plan",
      total: "CAST(a.form_data ->> 'total' AS NUMERIC)",
      status: "a.status",
      vendor_name: "u.full_name",
      fecha_creacion: "a.fecha_creacion",
    };
    const orderByColumn = orderByMap[sortBy] || "a.fecha_creacion";
    const orderDirection = descending === "true" ? "DESC" : "ASC";

    const finalParams = [...params];
    if (limit !== null) {
      finalParams.push(limit);
    }
    finalParams.push(offset);

    const query = `
      SELECT
        a.id, a.titular_nombre, a.titular_dni, a.plan, a.status, a.fecha_creacion,
        a.form_data ->> 'total' as total,
        u.full_name as vendor_name
      FROM affiliations a
      JOIN users u ON a.user_id = u.id
      ${whereCondition}
      ORDER BY ${orderByColumn} ${orderDirection}
      ${limit !== null ? `LIMIT $${paramCounter++}` : ""}
      OFFSET $${paramCounter++}
    `;

    const result = await pool.query(query, finalParams);

    res.json({
      rows: result.rows,
      totalRows: totalRows,
    });
  } catch (error) {
    console.error("Error al obtener afiliaciones:", error);
    res.status(500).json({ message: "Error al obtener afiliaciones." });
  }
});

app.get("/api/affiliations/:id", authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { userId, role } = req.user;

  try {
    let query = `
          SELECT 
              a.*, 
              creator.full_name as creator_user_name,
              creator.codigo as creator_user_codigo,
              status_changer.full_name as status_change_user_name 
          FROM affiliations a
          JOIN users creator ON a.user_id = creator.id
          LEFT JOIN users status_changer ON a.status_change_user_id = status_changer.id
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

    const fotosResult = await pool.query(
      "SELECT id, public_id, descripcion, fecha_subida FROM afiliacion_fotos WHERE afiliacion_id = $1 ORDER BY fecha_subida DESC",
      [id]
    );

    const fotosConUrlSegura = fotosResult.rows.map((foto) => {
      const urlFirmada = cloudinary.url(foto.public_id, {
        type: "authenticated",
        sign_url: true,
        expires_at: Math.floor(Date.now() / 1000) + 3600,
      });
      return {
        ...foto,
        url_segura: urlFirmada,
      };
    });

    const dbRow = result.rows[0];

    const affiliationDetails = {
      ...dbRow.form_data,
      id: dbRow.id,
      solicitud: dbRow.form_data.solicitud,
      latitud: dbRow.latitud,
      longitud: dbRow.longitud,
      status: dbRow.status,
      statusChangeTimestamp: dbRow.status_change_timestamp,
      statusChangeUserName: dbRow.status_change_user_name,
      rechazoMotivo: dbRow.rechazo_motivo,
      creatorUserName: dbRow.creator_user_name,
      creatorUserCodigo: dbRow.creator_user_codigo,
      domicilio_latitud: dbRow.domicilio_latitud,
      domicilio_longitud: dbRow.domicilio_longitud,
      fotos: fotosConUrlSegura,
    };

    res.json(affiliationDetails);
  } catch (error) {
    console.error("Error al obtener detalle:", error);
    res.status(500).json({ message: "Error interno del servidor." });
  }
});

app.put(
  "/api/affiliations/:id/status",
  authenticateToken,
  authorize(["SUPERVISOR", "ADMINISTRADOR"]),
  async (req, res) => {
    const { id } = req.params;
    const { newStatus, motivo } = req.body;
    const changingUserId = req.user.userId;

    if (!["Aprobado", "Rechazado"].includes(newStatus)) {
      return res.status(400).json({ message: "Estado no válido." });
    }
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

      const result = await pool.query(
        `UPDATE affiliations 
         SET status = $1, status_change_user_id = $2, status_change_timestamp = NOW(), rechazo_motivo = $3 
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

// --- ENDPOINT PARA SUBIR FOTOS A UNA AFILIACIÓN ---
app.post(
  "/api/affiliations/:id/fotos",
  authenticateToken,
  authorize(["VENDEDOR", "SUPERVISOR", "ADMINISTRADOR"]),
  upload.single("foto"),
  async (req, res) => {
    const { id } = req.params;
    const { descripcion } = req.body;

    if (!req.file) {
      return res
        .status(400)
        .json({ message: "No se ha subido ningún archivo." });
    }

    try {
      const uploadResult = await new Promise((resolve, reject) => {
        const uploadStream = cloudinary.uploader.upload_stream(
          {
            folder: `afiliaciones/${id}`,
            public_id: `${Date.now()}`,
            type: "authenticated",
          },
          (error, result) => {
            if (error) {
              return reject(error);
            }
            resolve(result);
          }
        );

        uploadStream.end(req.file.buffer);
      });

      const { public_id } = uploadResult;

      const newFoto = await pool.query(
        "INSERT INTO afiliacion_fotos (afiliacion_id, public_id, descripcion) VALUES ($1, $2, $3) RETURNING *",
        [id, public_id, descripcion]
      );

      res.status(201).json(newFoto.rows[0]);
    } catch (error) {
      console.error(
        "Error al subir la foto a la afiliación con ID:",
        id,
        error
      );
      res
        .status(500)
        .json({ message: "Error interno del servidor al procesar la foto." });
    }
  }
);

// ENDPOINT PARA LOS DATOS DEL DASHBOARD

app.post(
  "/api/dashboard",
  authenticateToken,
  authorize(["SUPERVISOR", "GERENTE", "ADMINISTRADOR"]),
  async (req, res) => {
    const {
      startDate,
      endDate,
      selectedVendor,
      selectedPlan,
      selectedMedioPago,
      selectedEmpresa,
    } = req.body;

    if (!startDate || !endDate) {
      return res
        .status(400)
        .json({ message: "Se requiere un rango de fechas." });
    }

    try {
      const finalEndDate = new Date(endDate);
      finalEndDate.setDate(finalEndDate.getDate() + 1);

      let params = [startDate, finalEndDate];
      let paramCounter = 3;
      let whereClauses = [];

      if (selectedVendor) {
        whereClauses.push(`u.full_name = $${paramCounter++}`);
        params.push(selectedVendor);
      }
      if (selectedPlan) {
        whereClauses.push(`a.plan = $${paramCounter++}`);
        params.push(selectedPlan);
      }
      if (selectedMedioPago) {
        whereClauses.push(`a.form_data ->> 'medioPago' = $${paramCounter++}`);
        params.push(selectedMedioPago);
      }
      if (selectedEmpresa) {
        whereClauses.push(`a.form_data ->> 'empresa' = $${paramCounter++}`);
        params.push(selectedEmpresa);
      }

      const affiliationsQuery = `
            SELECT 
                a.id, a.status, a.latitud, a.longitud, a.domicilio_latitud, a.domicilio_longitud, a.fecha_creacion, a.plan,
                a.form_data ->> 'total' as total,
                u.full_name as vendor_name
            FROM affiliations a
            JOIN users u ON a.user_id = u.id
            WHERE a.fecha_creacion >= $1 AND a.fecha_creacion < $2
            ${
              whereClauses.length > 0 ? "AND " + whereClauses.join(" AND ") : ""
            }
        `;

      const affiliationsResult = await pool.query(affiliationsQuery, params);
      const affiliations = affiliationsResult.rows;

      const totalFichas = affiliations.length;
      const fichasAprobadas = affiliations.filter(
        (f) => f.status === "Aprobado"
      ).length;
      const fichasRechazadas = affiliations.filter(
        (f) => f.status === "Rechazado"
      ).length;
      const fichasPendientes = affiliations.filter(
        (f) => f.status === "Presentado"
      ).length;

      const ventasTotales = affiliations
        .filter((f) => f.status === "Aprobado" && f.total)
        .reduce((sum, f) => sum + parseFloat(f.total), 0);

      const ventasPorVendedor = affiliations.reduce((acc, f) => {
        if (f.status === "Aprobado") {
          acc[f.vendor_name] = (acc[f.vendor_name] || 0) + 1;
        }
        return acc;
      }, {});

      const [topVendedor, topVendedorVentas] = Object.entries(
        ventasPorVendedor
      ).sort(([, a], [, b]) => b - a)[0] || ["N/A", 0];

      const planesVendidos = affiliations.reduce((acc, f) => {
        if (f.status === "Aprobado" && f.plan) {
          acc[f.plan] = (acc[f.plan] || 0) + 1;
        }
        return acc;
      }, {});
      const [topPlan, topPlanVentas] = Object.entries(planesVendidos).sort(
        ([, a], [, b]) => b - a
      )[0] || ["N/A", 0];

      const ventasPorDia = affiliations.reduce((acc, f) => {
        if (f.status === "Aprobado") {
          const dia = new Date(f.fecha_creacion).toISOString().split("T")[0];
          acc[dia] = (acc[dia] || 0) + 1;
        }
        return acc;
      }, {});

      const locations = affiliations
        .map((f) => ({
          id: f.id,
          status: f.status,

          venta: {
            lat: f.latitud ? parseFloat(f.latitud) : null,
            lng: f.longitud ? parseFloat(f.longitud) : null,
          },

          domicilio: {
            lat: f.domicilio_latitud ? parseFloat(f.domicilio_latitud) : null,
            lng: f.domicilio_longitud ? parseFloat(f.domicilio_longitud) : null,
          },
        }))
        .filter(
          (f) =>
            (f.venta.lat && f.venta.lng) || (f.domicilio.lat && f.domicilio.lng)
        );

      const dashboardData = {
        kpis: {
          totalFichas,
          fichasAprobadas,
          fichasRechazadas,
          fichasPendientes,
          tasaAprobacion:
            totalFichas > 0
              ? ((fichasAprobadas / totalFichas) * 100).toFixed(1) + "%"
              : "0%",
          ventasTotales: ventasTotales,
          ticketPromedio:
            fichasAprobadas > 0 ? ventasTotales / fichasAprobadas : 0,
          topVendedor: topVendedor,
          topVendedorVentas,
          topPlan,
          topPlanVentas,
          ventasPorDia,
        },
        locations,
      };

      res.json(dashboardData);
    } catch (error) {
      console.error("Error al obtener datos del dashboard:", error);
      res.status(500).json({ message: "Error interno del servidor." });
    }
  }
);

// --- ENDPOINT PARA GENERAR PDF DE UNA AFILIACIÓN ---
app.get("/api/affiliations/:id/pdf", authenticateToken, async (req, res) => {
  let browser = null;
  try {
    const { id } = req.params;

    // 1. OBTENER DATOS DE LA AFILIACIÓN (similar al GET de detalles)
    const result = await pool.query(
      "SELECT * FROM affiliations WHERE id = $1",
      [id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ message: "Afiliación no encontrada." });
    }
    const affiliationData = {
      ...result.rows[0].form_data, // Datos del JSON
      ...result.rows[0], // Datos de las columnas principales
    };

    // (Lógica para obtener nombre del promotor, etc., si es necesario)

    // 2. LEER Y COMPILAR LA PLANTILLA
    const templateHtmlPath = path.join(
      __dirname,
      "templates",
      "afiliacion.hbs"
    );
    const stylesCssPath = path.join(__dirname, "templates", "styles.css");

    const templateHtml = await fs.readFile(templateHtmlPath, "utf8");
    const cssContent = await fs.readFile(stylesCssPath, "utf8");

    const template = handlebars.compile(templateHtml);

    // Añadimos el CSS al objeto de datos para que se inyecte en la plantilla
    const dataForPdf = { ...affiliationData, cssContent: cssContent };

    const finalHtml = template(dataForPdf);

    // 3. LANZAR PUPPETEER Y GENERAR PDF
    browser = await puppeteer.launch({
      args: ["--no-sandbox", "--disable-setuid-sandbox"], // Necesario para correr en Render
    });
    const page = await browser.newPage();

    // Establecemos el contenido de la página
    await page.setContent(finalHtml, { waitUntil: "networkidle0" });

    const pdfBuffer = await page.pdf({
      format: "A4",
      printBackground: true,
      margin: { top: "10mm", right: "10mm", bottom: "10mm", left: "10mm" },
    });

    // 4. ENVIAR PDF AL CLIENTE
    res.setHeader("Content-Type", "application/pdf");
    res.setHeader(
      "Content-Disposition",
      `attachment; filename=solicitud-${affiliationData.solicitud || id}.pdf`
    );
    res.send(pdfBuffer);
  } catch (error) {
    console.error("Error al generar el PDF:", error);
    res.status(500).json({ message: "No se pudo generar el PDF." });
  } finally {
    // Asegurarnos de cerrar el navegador SIEMPRE
    if (browser) {
      await browser.close();
    }
  }
});

// --- DATOS MAESTROS ---

// Endpoints de lectura
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

// ABM de Planes
app.post(
  "/api/planes",
  authenticateToken,
  authorize(["ADMINISTRADOR"]),
  async (req, res) => {
    const {
      label,
      value,
      tipo,
      importe_grupo_familiar,
      importe_individual,
      importe_adherente,
      titulo,
    } = req.body;

    if (
      !label ||
      !value ||
      !tipo ||
      !importe_grupo_familiar ||
      !importe_individual ||
      !importe_adherente ||
      !titulo
    ) {
      return res
        .status(400)
        .json({ message: "Todos los campos son obligatorios." });
    }
    try {
      const newPlan = await pool.query(
        `INSERT INTO planes (
            label, value, tipo, 
            importe_grupo_familiar, importe_individual, importe_adherente, titulo
         ) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *`,
        [
          label,
          value,
          tipo,
          importe_grupo_familiar,
          importe_individual,
          importe_adherente,
          titulo,
        ]
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
    const {
      label,
      value,
      tipo,
      importe_grupo_familiar,
      importe_individual,
      importe_adherente,
      titulo,
    } = req.body;

    if (
      !label ||
      !value ||
      !tipo ||
      !importe_grupo_familiar ||
      !importe_individual ||
      !importe_adherente ||
      !titulo
    ) {
      return res
        .status(400)
        .json({ message: "Todos los campos son obligatorios." });
    }
    try {
      const updatedPlan = await pool.query(
        `UPDATE planes 
         SET label = $1, value = $2, tipo = $3, 
             importe_grupo_familiar = $4, importe_individual = $5, 
             importe_adherente = $6, titulo = $7 
         WHERE id = $8 RETURNING *`,
        [
          label,
          value,
          tipo,
          importe_grupo_familiar,
          importe_individual,
          importe_adherente,
          titulo,
          id,
        ]
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
        return res.status(409).json({
          message:
            "No se puede eliminar el plan porque está siendo utilizado por una o más afiliaciones.",
        });
      }
      res.status(500).json({ message: "Error al eliminar el plan." });
    }
  }
);

// ABM de Empresas
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
    try {
      const usage = await pool.query(
        "SELECT 1 FROM affiliations WHERE form_data ->> 'empresa' = (SELECT value FROM empresas WHERE id = $1) LIMIT 1",
        [id]
      );
      if (usage.rows.length > 0) {
        return res.status(409).json({
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
// -----------------------------------------------------------------------------
app.listen(PORT, () => {
  console.log(`🚀 Servidor backend corriendo en el puerto ${PORT}`);
});
