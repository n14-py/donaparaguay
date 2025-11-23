// =============================================
//               SERVER.JS - PARTE 1 DE 4
//      (NUEVA VERSIÓN PARA DONA PARAGUAY)
// =============================================

// IMPORTACIONES Y CONFIGURACIÓN INICIAL
// =============================================
require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const path = require('path');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const multer = require('multer');
const ejs = require('ejs');
const crypto = require('crypto');
const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const fetch = require('node-fetch');
const rateLimit = require('express-rate-limit');
const { JSDOM } = require('jsdom');
const DOMPurify = require('dompurify');
const nodemailer = require('nodemailer');
const speakeasy = require('speakeasy');
const cookieParser = require('cookie-parser');
const PDFDocument = require('pdfkit');
const fs = require('fs');

const window = new JSDOM('').window;
const purify = DOMPurify(window);
const app = express();
const PORT = process.env.PORT || 3000;


app.set('trust proxy', 1);

app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'html');
app.engine('html', ejs.renderFile);

// =============================================
// CONEXIÓN A MONGODB
// =============================================
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/donaparaguay_db')
  .then(async () => {
      console.log('✅ Conectado a MongoDB para Dona Paraguay');
      
      // --- ROBOT DE MIGRACIÓN DE CATEGORÍAS (CEO UPDATE) ---
      try {
          console.log('🔄 Ejecutando migración de categorías...');
          // Mapeo: Vieja -> Nueva
          await Campaign.updateMany({ category: 'Educación' }, { category: 'Universidad y Colegios' });
          await Campaign.updateMany({ category: 'Animales' }, { category: 'Rescate y Adopción' });
          await Campaign.updateMany({ category: 'Comunitario' }, { category: 'Ayuda Comunitaria' });
          await Campaign.updateMany({ category: 'Arte y Cultura' }, { category: 'Proyectos Personales' });
          await Campaign.updateMany({ category: 'Deportes' }, { category: 'Hobbies y Pasatiempos' });
          await Campaign.updateMany({ category: 'Otro' }, { category: 'Ayuda Comunitaria' }); // "Otro" va a Comunitario por seguridad
          console.log('✅ Migración de categorías completada con éxito.');
      } catch (error) {
          console.error('⚠️ Error en la migración automática:', error);
      }
      // ----------------------------------------------------
  })
  .catch(err => console.error('❌ Error de conexión a MongoDB:', err));

// =============================================
// CONFIGURACIÓN DE CLOUDINARY
// =============================================
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

const getPublicId = (url) => {
    try {
        if (!url || !url.includes('cloudinary')) return null;
        const parts = url.split('/');
        const versionIndex = parts.findIndex(part => part.startsWith('v'));
        if (versionIndex === -1) return null;
        const publicIdWithFormat = parts.slice(versionIndex + 1).join('/');
        return publicIdWithFormat.substring(0, publicIdWithFormat.lastIndexOf('.'));
    } catch (e) { console.error("Error extrayendo public_id:", e); return null; }
};

// Configuración para las imágenes (campañas, perfiles, comprobantes)
// Configuración para las imágenes (campañas, perfiles, comprobantes)
const storage = new CloudinaryStorage({
    cloudinary: cloudinary,
    params: {
        folder: (req, file) => {
            // Guardar comprobantes en una carpeta separada y privada si es posible
            if (file.fieldname === 'proof') return 'donaparaguay/proofs';
            return 'donaparaguay/assets';
        },
        resource_type: 'image', // FORZAR SOLO IMÁGENES (Antes estaba 'auto')
        allowed_formats: ['jpeg', 'png', 'jpg', 'webp'], // Eliminamos mp4, mov, avi
        transformation: [
            { quality: "auto:good", fetch_format: "auto" } // Optimización automática
        ]
    }
});

const upload = multer({ storage: storage });

// =============================================
// CONFIGURACIÓN DE NODEMAILER
// =============================================

// Transportador principal para correos a usuarios
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
    },
});

// Transportador secundario para enviar notificaciones AL ADMIN
let adminTransporter;
if (process.env.ADMIN_EMAIL_USER && process.env.ADMIN_EMAIL_PASS) {
    adminTransporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: process.env.ADMIN_EMAIL_USER,
            pass: process.env.ADMIN_EMAIL_PASS,
        },
    });
    console.log('✅ Transportador de notificaciones para admin configurado.');
} else {
    console.log('⚠️ ADVERTENCIA: No se configuraron las credenciales para el correo de notificaciones de admin.');
}

// =============================================
// CONSTANTES Y MODELOS DE DATOS
// =============================================
// --- NUEVAS CATEGORÍAS ORGANIZADAS ---
const CATEGORY_GROUPS = {
    "🚨 URGENCIAS / NECESIDADES": [
        "Salud y Medicina", "Emergencias", "Accidentes y Tratamientos",
        "Medicamentos y Terapias", "Desastres (Incendio, robo, inundación)",
        "Mascotas y Veterinaria (urgente)", "Funerales y Ayuda Familiar"
    ],
    "🎓 EDUCACIÓN / FUTURO": [
        "Útiles y Materiales Escolares", "Universidad y Colegios",
        "Cursos y Certificaciones", "Becas y Oportunidades",
        "Tecnología para estudiar"
    ],
    "🏠 HOGAR / VIDA DIARIA": [
        "Alimentos y Despensa", "Alquiler y Vivienda",
        "Electrodomésticos", "Muebles y Hogar", "Facturas y Servicios"
    ],
    "🐶 ANIMALES / MASCOTAS": [
        "Rescate y Adopción", "Tratamientos Veterinarios",
        "Comida para Mascotas", "Esterilización / Vacunas"
    ],
    "💼 NEGOCIOS / CREACIÓN": [
        "Emprendimientos", "Capital Semilla", "Herramientas de Trabajo",
        "Equipos para emprender"
    ],
    "🚀 SUEÑOS / METAS": [
        "Viajes", "Cumpleaños / Fiestas", "Sueños de Vida",
        "Proyectos Personales", "Hobbies y Pasatiempos"
    ],
    "📱 TECNOLOGÍA / GUSTOS": [
        "Celulares", "Computadoras / Laptops", "Consolas / Videojuegos",
        "Accesorios tecnológicos"
    ],
    "💎 DESEOS / CAPRICHOS": [
        "Autoregalo", "Gustos Personales", "Moda y Ropa", "Cosméticos y Belleza"
    ],
    "❤️ CAUSAS SOCIALES": [
        "Ayuda Comunitaria", "Organizaciones y ONG",
        "Protección Animal", "Eventos Solidarios", "Medio Ambiente"
    ]
};

// Generamos la lista plana para validación de Mongoose
const CATEGORIES = Object.values(CATEGORY_GROUPS).flat();
const CITIES = ['Asunción', 'Central', 'Ciudad del Este', 'Encarnación', 'Villarrica', 'Coronel Oviedo', 'Pedro Juan Caballero', 'Otra'];

const BADGES = [
    { name: 'Primer Donativo', description: '¡Gracias por dar el primer paso y realizar tu primera donación!', icon: 'fa-hand-holding-heart', criteria: { type: 'donations_count', value: 1 } },
    { name: 'Donante Generoso', description: 'Donaste más de 100.000 Gs. en una sola contribución. ¡Increíble!', icon: 'fa-gem', criteria: { type: 'single_donation_amount', value: 100000 } },
    { name: 'Corazón de Oro', description: 'Has donado más de 500.000 Gs. en total. Tu generosidad no tiene límites.', icon: 'fa-crown', criteria: { type: 'total_donation_amount', value: 500000 } },
    { name: 'Amigo Fiel', description: 'Has apoyado a 3 campañas diferentes.', icon: 'fa-users', criteria: { type: 'unique_campaigns_donated', value: 3 } },
    { name: 'Pionero Solidario', description: 'Fuiste uno de los primeros 10 donantes de una campaña.', icon: 'fa-rocket', criteria: { type: 'first_x_donors', value: 10 } },
    { name: 'Causa Animal', description: 'Realizaste una donación a una campaña de la categoría Animales.', icon: 'fa-paw', criteria: { type: 'category_donation', value: 'Animales' } },
    { name: 'Pro-Educación', description: 'Realizaste una donación a una campaña de la categoría Educación.', icon: 'fa-book-open', criteria: { type: 'category_donation', value: 'Educación' } },
    { name: 'Héroe de la Salud', description: 'Realizaste una donación a una campaña de la categoría Salud y Medicina.', icon: 'fa-briefcase-medical', criteria: { type: 'category_donation', value: 'Salud y Medicina' } },
    { name: 'Constructor Comunitario', description: 'Realizaste una donación a una campaña de la categoría Comunitario.', icon: 'fa-people-carry', criteria: { type: 'category_donation', value: 'Comunitario' } },
    { name: 'Madrugador', description: 'Hiciste una donación dentro de las primeras 24 horas de una campaña.', icon: 'fa-stopwatch', criteria: { type: 'early_donor', value: 24 } }
];


const badgeSchema = new mongoose.Schema({
    name: { type: String, required: true },
    description: { type: String, required: true },
    icon: { type: String, required: true } // e.g., 'fa-heart', 'fa-fist-raised'
});

// EN la sección de userSchema, añadir los nuevos campos:
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true, lowercase: true, trim: true },
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    password: { type: String },
    googleId: { type: String },
    phone: { type: String },
    bio: String,
    profilePic: { type: String, default: 'https://res.cloudinary.com/dmedd6w1q/image/upload/v1760503254/jdb01r30behkffswtrqu_zzcqdy.png' },
    isVerified: { type: Boolean, default: false },
    isBanned: { type: Boolean, default: false },
    role: { type: String, enum: ['User', 'Admin', 'Moderator'], default: 'User' },
    permissions: [{ type: String }],
    securityQuestions: [{ question: String, answer: String }],
    verificationCode: String,
    verificationCodeExpires: Date,
    verificationSecret: { type: String },
    isVerifiedEmail: { type: Boolean, default: false },
    followers: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    following: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    privacySettings: { showDonations: { type: Boolean, default: true } },
    badges: [badgeSchema],
    // --- NUEVOS CAMPOS ---
    gender: { type: String, enum: ['Masculino', 'Femenino', 'Otro', 'Prefiero no decirlo'] },
    location: { type: String },
    socialLinks: {
        facebook: { type: String },
        instagram: { type: String },
        twitter: { type: String }
    }
}, { timestamps: true });


const auditLogSchema = new mongoose.Schema({
    adminId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    action: { type: String, required: true },
    targetUserId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    targetCampaignId: { type: mongoose.Schema.Types.ObjectId, ref: 'Campaign' },
    details: { type: String }
}, { timestamps: true });

const sponsorSchema = new mongoose.Schema({
    companyName: { type: String, required: true },
    companyWebsite: { type: String, required: true },
    contactEmail: { type: String, required: true },
    companyLogo: { type: String, required: true },
    paymentProofUrl: { type: String, required: true },
    months: { type: Number, required: true },
    totalAmount: { type: Number, required: true },
    status: { type: String, enum: ['pending', 'active', 'expired'], default: 'pending' },
    approvedAt: { type: Date },
    expiresAt: { type: Date }
}, { timestamps: true });

const Sponsor = mongoose.model('Sponsor', sponsorSchema);

const campaignSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, // El organizador
    title: { type: String, required: true },
    description: String,
    files: [String],
    category: { type: String, enum: CATEGORIES },
    location: { type: String, enum: CITIES },
    goalAmount: { type: Number, default: 0 }, // Meta en Guaraníes
    amountRaised: { type: Number, default: 0 }, // Recaudado en Guaraníes
    views: { type: Number, default: 0 },
    status: { type: String, enum: ['pending', 'approved', 'rejected', 'completed', 'hidden', 'pending_verification'], default: 'pending' },
    likes: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    // --- LÍNEA NUEVA A AÑADIR ---
    milestonesNotified: { type: Map, of: Boolean, default: {} }
}, { timestamps: true });

const verificationSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, unique: true },
    frontIdPhoto: { type: String, required: true },
    backIdPhoto: { type: String, required: true },
    status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
    rejectionReason: { type: String }
}, { timestamps: true });

const reportSchema = new mongoose.Schema({
    reportingUserId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    reportedUserId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    reportedCampaignId: { type: mongoose.Schema.Types.ObjectId, ref: 'Campaign' },
    type: { type: String, enum: ['user', 'campaign'], required: true },
    category: { type: String, required: true },
    reason: { type: String },
    status: { type: String, enum: ['pendiente', 'revisado'], default: 'pendiente' }
}, { timestamps: true });

const transactionSchema = new mongoose.Schema({
    type: { type: String, enum: ['donation', 'withdrawal', 'platform_fee', 'admin_adjustment'] },
    donatorId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    organizerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    campaignId: { type: mongoose.Schema.Types.ObjectId, ref: 'Campaign' },
    amount: Number, // Monto en Guaraníes
    platformFee: { type: Number, default: 0 },
    netAmount: { type: Number, default: 0 },
    paymentGatewayId: String,
    status: { type: String, enum: ['COMPLETADO', 'CANCELADO'], default: 'COMPLETADO' }
}, { timestamps: true });

const manualDonationSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    campaignId: { type: mongoose.Schema.Types.ObjectId, ref: 'Campaign', required: true },
    amount: { type: Number, required: true }, // Monto TOTAL transferido
    campaignAmount: { type: Number, required: true }, // Parte para la campaña
    platformTip: { type: Number, default: 0 }, // Parte para la plataforma
    proofImageUrl: { type: String, required: true }, // Comprobante
    status: { type: String, enum: ['Pendiente', 'Aprobado', 'Rechazado'], default: 'Pendiente' },
    // --- LÍNEA NUEVA ---
    comment: { type: String, trim: true, maxLength: 280 } // Mensaje de apoyo
}, { timestamps: true });

const withdrawalSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, // El organizador que retira
    campaignId: { type: mongoose.Schema.Types.ObjectId, ref: 'Campaign' }, // De qué campaña retira
    amount: Number, // Monto en Guaraníes
    method: String,
    details: { fullName: String, ci: String, bankName: String, accountNumber: String, phone: String, alias: String },
    status: { type: String, enum: ['Pendiente', 'Procesado', 'Rechazado'], default: 'Pendiente' }
}, { timestamps: true });

const notificationSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    actorId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    type: { type: String, enum: ['comment', 'donation', 'campaign_approved', 'admin'] },
    campaignId: { type: mongoose.Schema.Types.ObjectId, ref: 'Campaign' },
    isRead: { type: Boolean, default: false },
    message: String,
}, { timestamps: true });

const updateSchema = new mongoose.Schema({
    campaignId: { type: mongoose.Schema.Types.ObjectId, ref: 'Campaign', required: true },
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    content: { type: String, required: true, trim: true }
}, { timestamps: true });

const commentSchema = new mongoose.Schema({
    campaignId: { type: mongoose.Schema.Types.ObjectId, ref: 'Campaign', required: true },
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    text: { type: String, required: true, trim: true },
    parentCommentId: { type: mongoose.Schema.Types.ObjectId, ref: 'Comment', default: null },
    // Campos nuevos para manejar anidación y respuestas
    replies: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Comment' }],
    depth: { type: Number, default: 0 } 
}, { timestamps: true });

// Busca este bloque en server.js
// Busca este bloque en server.js
const siteConfigSchema = new mongoose.Schema({
    configKey: { type: String, default: 'main_config', unique: true },
    verificationRequired: { type: Boolean, default: true },
    platformFeeRate: { type: Number, default: 0.10, min: 0, max: 1 }, // 10% de comisión por defecto
    cities: { type: [String], default: CITIES },
    categories: { type: [String], default: CATEGORIES },
    maxSponsorSlots: { type: Number, default: 10 },
    // --- LÍNEAS MODIFICADAS Y AÑADIDAS ---
    bankAccounts: [{
        bankName: String,
        accountHolderName: String,
        accountNumber: String,
        ci: String,
        details: String // Para alias, etc.
    }],
    activeBankAccountId: { type: mongoose.Schema.Types.ObjectId }
});


// Declaración de todos los modelos
const User = mongoose.model('User', userSchema);
const Campaign = mongoose.model('Campaign', campaignSchema);
const Verification = mongoose.model('Verification', verificationSchema);
const Report = mongoose.model('Report', reportSchema);
const Transaction = mongoose.model('Transaction', transactionSchema);
const ManualDonation = mongoose.model('ManualDonation', manualDonationSchema);
const Withdrawal = mongoose.model('Withdrawal', withdrawalSchema);
const Notification = mongoose.model('Notification', notificationSchema);
const AuditLog = mongoose.model('AuditLog', auditLogSchema);
const Update = mongoose.model('Update', updateSchema);
const Comment = mongoose.model('Comment', commentSchema);




// --- INICIO: LÓGICA DE INSIGNIAS ---
async function awardBadges(userId, donation) {
    try {
        const user = await User.findById(userId);
        if (!user) return;

        const userBadgeNames = user.badges.map(b => b.name);
        let newBadges = [];

        // Obtener datos agregados del usuario
        const allDonations = await ManualDonation.find({ userId: user._id, status: 'Aprobado' });
        const donationsCount = allDonations.length;
        const totalDonated = allDonations.reduce((sum, d) => sum + d.campaignAmount, 0);
        const uniqueCampaigns = [...new Set(allDonations.map(d => d.campaignId.toString()))].length;

        for (const badge of BADGES) {
            if (userBadgeNames.includes(badge.name)) continue; // Ya tiene esta insignia

            let earned = false;
            const criteria = badge.criteria;

            switch (criteria.type) {
                case 'donations_count':
                    if (donationsCount >= criteria.value) earned = true;
                    break;
                case 'single_donation_amount':
                    if (donation.campaignAmount >= criteria.value) earned = true;
                    break;
                case 'total_donation_amount':
                    if (totalDonated >= criteria.value) earned = true;
                    break;
                case 'unique_campaigns_donated':
                    if (uniqueCampaigns >= criteria.value) earned = true;
                    break;
                case 'category_donation':
                    const campaign = await Campaign.findById(donation.campaignId);
                    if (campaign && campaign.category === criteria.value) earned = true;
                    break;
                // Los criterios 'first_x_donors' y 'early_donor' son más complejos y los implementaremos después si quieres.
            }

            if (earned) {
                newBadges.push(badge);
                // Notificar al usuario que ganó una insignia
                await new Notification({
                    userId: user._id,
                    type: 'admin',
                    message: `¡Felicidades! Has ganado la insignia: "${badge.name}".`
                }).save();
            }
        }

        if (newBadges.length > 0) {
            user.badges.push(...newBadges);
            await user.save();
        }
    } catch (error) {
        console.error('Error al otorgar insignias:', error);
    }
}
// --- FIN: LÓGICA DE INSIGNIAS ---


// =============================================
// MIDDLEWARES Y PASSPORT
// =============================================
const generalLimiter = rateLimit({
	windowMs: 15 * 60 * 1000, max: 200, standardHeaders: true, legacyHeaders: false,
});
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, max: 15, message: 'Demasiados intentos. Intenta de nuevo en 15 minutos.', standardHeaders: true, legacyHeaders: false,
});


const SiteConfig = mongoose.model('SiteConfig', siteConfigSchema);

app.use(async (req, res, next) => {
    try {
        let config = await SiteConfig.findOne({ configKey: 'main_config' });
        if (!config) {
            config = new SiteConfig();
            await config.save();
        }
        res.locals.siteConfig = config;
        res.locals.CITIES = config.cities;
        res.locals.CATEGORIES = config.categories;
        res.locals.CATEGORY_GROUPS = CATEGORY_GROUPS;

        // --- CÓDIGO AÑADIDO PARA BANCO ACTIVO ---
        if (config.activeBankAccountId) {
            res.locals.activeBankAccount = config.bankAccounts.id(config.activeBankAccountId);
        } else {
            res.locals.activeBankAccount = null;
        }
        // --- FIN DEL CÓDIGO AÑADIDO ---

        res.locals.currentUser = req.user;
        res.locals.formatDate = formatDate;
        res.locals.path = req.path;
        res.locals.query = req.query;
        res.locals.baseUrl = process.env.BASE_URL || `http://localhost:${PORT}`;
        res.locals.session = req.session;
        if (req.user) {
            res.locals.unreadNotifications = await Notification.countDocuments({ userId: req.user._id, isRead: false });
        } else {
            res.locals.unreadNotifications = 0;
        }
        next();
    } catch (err) {
        next(err);
    }
});

app.use(cookieParser());
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// REEMPLAZA LA LÍNEA DE "app.use(session...)" CON TODO ESTE NUEVO BLOQUE
const sessionStore = MongoStore.create({
  mongoUrl: process.env.MONGODB_URI || 'mongodb://localhost:27017/donaparaguay_db',
  collectionName: 'sessions',
  ttl: 10 * 24 * 60 * 60 // = 10 días
});

app.use(session({
    secret: process.env.SESSION_SECRET || 'dona-paraguay-super-secret-key',
    resave: false,
    saveUninitialized: false, // Cambiado a false
    store: sessionStore,
    cookie: {
        maxAge: 10 * 24 * 60 * 60 * 1000, // 10 días en milisegundos
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        sameSite: 'lax'
    }
}));
// HASTA AQUÍ LLEGA EL REEMPLAZO

app.use(passport.initialize());
app.use(passport.session());
app.use(express.static(path.join(__dirname, 'public')));

const formatDate = (date) => {
    if (!date) return '';
    const d = new Date(date);
    const now = new Date();
    const diffSeconds = Math.round((now - d) / 1000);
    if (diffSeconds < 60) return 'Justo ahora';
    const diffMinutes = Math.round(diffSeconds / 60);
    if (diffMinutes < 60) return `Hace ${diffMinutes} min`;
    const diffHours = Math.round(diffMinutes / 60);
    if (diffHours < 24) return `Hace ${diffHours} h`;
    return d.toLocaleDateString('es-PY');
};

app.use(async (req, res, next) => {
    res.locals.currentUser = req.user;
    res.locals.formatDate = formatDate;
    res.locals.path = req.path;
    res.locals.query = req.query;
    res.locals.baseUrl = process.env.BASE_URL || `http://localhost:${PORT}`;
    res.locals.session = req.session;
    if (req.user) {
        res.locals.unreadNotifications = await Notification.countDocuments({ userId: req.user._id, isRead: false });
    } else {
        res.locals.unreadNotifications = 0;
    }
    next();
});

passport.use(new LocalStrategy({ usernameField: 'email' }, async (email, password, done) => {
    try {
        const user = await User.findOne({ email: email.toLowerCase() });
        if (!user || !user.password) return done(null, false, { message: 'Credenciales incorrectas.' });
        if (user.isBanned) return done(null, false, { message: 'Esta cuenta ha sido suspendida.' });
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return done(null, false, { message: 'Credenciales incorrectas.' });
        return done(null, user);
    } catch (err) { return done(err); }
}));

const CALLBACK_URL = `${process.env.BASE_URL || 'http://localhost:3000'}/auth/google/callback`;
passport.use(new GoogleStrategy({ clientID: process.env.GOOGLE_CLIENT_ID, clientSecret: process.env.GOOGLE_CLIENT_SECRET, callbackURL: CALLBACK_URL },
  async (accessToken, refreshToken, profile, done) => {
    try {
        let user = await User.findOne({ email: profile.emails[0].value });
        if (user) {
            if (user.isBanned) return done(null, false, { message: 'Esta cuenta ha sido suspendida.' });
            if (!user.googleId) { user.googleId = profile.id; await user.save(); }
            return done(null, user);
        }
        const newUser = new User({
            googleId: profile.id,
            username: profile.displayName.replace(/\s/g, '').toLowerCase() + Math.floor(Math.random() * 1000),
            email: profile.emails[0].value,
            profilePic: profile.photos[0].value,
        });
        await newUser.save();
        return done(null, newUser);
    } catch (err) { return done(err, null); }
  }
));

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
    try {
        const user = await User.findById(id);
        done(null, user);
    } catch (err) {
        done(err);
    }
});

const requireAuth = (req, res, next) => {
    if (req.isAuthenticated()) {
        if (req.user.isBanned) {
            req.logout((err) => {
                if(err) return next(err);
                res.status(403).render('error', { message: 'Tu cuenta ha sido suspendida.' });
            });
        } else {
            return next();
        }
    } else {
        res.redirect('/login');
    }
};

const requireAdmin = (req, res, next) => (req.isAuthenticated() && req.user.role === 'Admin') ? next() : res.status(403).render('error', { message: "Acceso denegado." });

// Requiere que un usuario esté verificado para crear campañas
const requireVerification = async (req, res, next) => {
    const config = res.locals.siteConfig;
    // Si la verificación no es requerida, o si el usuario ya está verificado/es admin, puede pasar.
    if (!config.verificationRequired || (req.user && (req.user.isVerified || req.user.role === 'Admin'))) {
        return next();
    }
    // Si no, lo mandamos a la página de verificación con un mensaje.
    // Podrías usar connect-flash para un mensaje más elegante.
    res.redirect('/verify-account');
};

// =============================================
// HELPER PARA ENVIAR NOTIFICACIONES AL ADMIN
// =============================================
async function sendAdminNotificationEmail({ subject, message, actionUrl }) {
    // Verifica si el transportador y el destinatario están configurados
    if (!adminTransporter || !process.env.ADMIN_EMAIL_RECIPIENT) {
        console.log('ADVERTENCIA: El correo para notificaciones de admin no está configurado. No se enviará la alerta.');
        return;
    }

    try {
        const emailHtml = await ejs.renderFile(path.join(__dirname, 'views', 'emails', 'admin-notification.html'), {
            subject,
            message,
            actionUrl
        });

        await adminTransporter.sendMail({
            from: `"Alertas Dona Paraguay" <${process.env.ADMIN_EMAIL_USER}>`, // Envía DESDE notificaciones.donapy@gmail.com
            to: process.env.ADMIN_EMAIL_RECIPIENT,                         // Envía HACIA tu correo personal
            subject: `🔔 Alerta de Admin: ${subject}`,
            html: emailHtml
        });
    } catch (error) {
        console.error(`❌ Error al enviar correo de notificación al admin:`, error);
    }
}



// =============================================
// HELPER PARA ENVIAR CORREOS CON CÓDIGO (NUEVO)
// =============================================
async function sendCodeEmail({ email, username, code, title, subject, introMessage }) {
    try {
        const emailHtml = await ejs.renderFile(path.join(__dirname, 'views', 'emails', 'recovery-code.html'), {
            username,
            code,
            title,
            subject, // Asegúrate de que la plantilla use estas variables si es necesario
            introMessage
        });

        await transporter.sendMail({
            from: `"Soporte Dona Paraguay" <${process.env.EMAIL_USER}>`, // Usamos el correo principal
            to: email,
            subject: subject, // El asunto que pasaste como parámetro
            html: emailHtml
        });
        console.log(`✅ Correo de código enviado a ${email}`);
    } catch (error) {
        console.error(`❌ Error al enviar correo de código a ${email}:`, error);
        // Podrías querer lanzar el error aquí o manejarlo de otra forma
        // throw error; 
    }
}



// =============================================
// RUTAS DE AUTENTICACIÓN Y PÁGINAS BÁSICAS
// =============================================
app.get('/', async (req, res, next) => {
    try {
        // Solo necesitamos datos para la portada (Sponsors y tal vez categorías)
        const activeSponsors = await Sponsor.find({ status: 'active', expiresAt: { $gt: new Date() } }).sort({ createdAt: 1 });
        
        // Renderizamos la vista nueva 'home.html'
        res.render('home', {
            activeSponsors,
            pageTitle: 'Dona Paraguay - Conectando Corazones',
            pageDescription: 'La plataforma de crowdfunding de Paraguay.'
        });
    } catch (err) {
        next(err);
    }
});
app.get('/privacy', (req, res) => res.render('privacy'));
app.get('/terms', (req, res) => res.render('terms'));
app.get('/faq', (req, res) => res.render('faq'));

// --- NUEVAS RUTAS DE CONTENIDO ---
app.get('/about', (req, res) => res.render('about'));
app.get('/trust', (req, res) => res.render('trust'));
app.get('/how-it-works', (req, res) => res.render('how-it-works'));

// --- NUEVAS RUTAS DEL CENTRO DE AYUDA ---
app.get('/help-center', (req, res) => res.render('help-center'));

// Esta ruta manejará todos los artículos de forma dinámica y segura
const helpArticlesPath = path.join(__dirname, 'views', 'help-articles');
app.get('/help/article/:slug', (req, res, next) => {
    const slug = req.params.slug;
    // Sanitiza el slug para prevenir ataques de seguridad
    const safeSlug = path.normalize(slug).replace(/^(\.\.[\/\\])+/, '');
    const articlePath = path.join(helpArticlesPath, `${safeSlug}.html`);

    // Verifica si el archivo existe antes de intentar mostrarlo
    fs.access(articlePath, fs.constants.F_OK, (err) => {
        if (err) {
            // Si el archivo no se encuentra, pasa al manejador de errores 404
            console.error(`Artículo de ayuda no encontrado: ${articlePath}`);
            return next(); 
        }
        
        // Si el archivo existe, lo renderiza
        res.render(`help-articles/${safeSlug}.html`);
    });
});
// --- FIN DE NUEVAS RUTAS ---


app.get('/register', (req, res) => res.render('register', { error: null }));
// REEMPLAZAR la ruta app.post('/register', ...) con este nuevo código:
app.post('/register', loginLimiter, async (req, res, next) => {
    try {
        const { username, email, password, phone, gender } = req.body;
        if (!username || !email || !password) throw new Error("Todos los campos son obligatorios.");

        const existingUser = await User.findOne({ $or: [{ email: email.toLowerCase() }, { username: username.toLowerCase() }] });
        if (existingUser) throw new Error('El email o nombre de usuario ya está en uso.');

        const hashedPassword = await bcrypt.hash(password, 12);
        
        const user = new User({ 
            username, 
            email, 
            password: hashedPassword, 
            phone,
            gender,
            isVerifiedEmail: true // El email se considera verificado al registrarse
        });
        await user.save();

        // Iniciar sesión automáticamente al usuario
        req.login(user, (err) => {
            if (err) return next(err);
            // Redirigir al perfil del usuario recién creado
            res.redirect('/profile');
        });

    } catch (err) {
        res.render('register', { error: err.message });
    }
});


app.get('/verify-2fa', async (req, res) => {
    if (!req.session.verifyUserId) return res.redirect('/login');
    const user = await User.findById(req.session.verifyUserId).select('email');
    res.render('verify-2fa', { error: null, email: user ? user.email : '' });
});

app.post('/verify-2fa', async (req, res, next) => {
    try {
        const { token } = req.body;
        const userId = req.session.verifyUserId;
        if (!userId) return res.redirect('/login');

        const user = await User.findById(userId);
        if (!user) throw new Error('Usuario no encontrado.');

        const isValid = speakeasy.totp.verify({
            secret: user.verificationSecret, encoding: 'base32', token, window: 2
        });

        if (isValid) {
            user.isVerifiedEmail = true;
            await user.save();
            delete req.session.verifyUserId;
            req.login(user, (err) => {
                if (err) return next(err);
                res.redirect('/campaigns');
            });
        } else {
            res.render('verify-2fa', { error: 'Código inválido o expirado.', email: user.email });
        }
    } catch (err) {
        next(err);
    }
});


// PEGA ESTE CÓDIGO CORREGIDO
app.get('/verify-account', requireAuth, async (req, res, next) => {
    try {
        const existingVerification = await Verification.findOne({ userId: req.user._id });

        // Si la verificación ya está pendiente, muestra la página de espera.
        if (existingVerification && existingVerification.status === 'pending') {
            return res.render('verify-pending.html');
        }

        // Si no está pendiente (o no existe), muestra el formulario de carga.
        res.render('verify-account', {
            status: existingVerification ? existingVerification.status : null,
            reason: existingVerification ? existingVerification.rejectionReason : null
        });
    } catch (err) {
        next(err);
    }
});

// PEGA ESTE CÓDIGO CORREGIDO
app.post('/verify-account', requireAuth, upload.fields([
    { name: 'frontIdPhoto', maxCount: 1 },
    { name: 'backIdPhoto', maxCount: 1 }
]), async (req, res, next) => {
    try {
        if (!req.files || !req.files.frontIdPhoto || !req.files.backIdPhoto) {
            return res.status(400).render('verify-account', {
                error: 'Debes subir ambos archivos (frente y reverso).',
                status: null,
                reason: null
            });
        }

        await Verification.findOneAndUpdate(
            { userId: req.user._id },
            {
                userId: req.user._id,
                frontIdPhoto: req.files.frontIdPhoto[0].path,
                backIdPhoto: req.files.backIdPhoto[0].path,
                status: 'pending',
                rejectionReason: null
            },
            { upsert: true, new: true, setDefaultsOnInsert: true }
        );

        await sendAdminNotificationEmail({
        subject: 'Nueva Solicitud de Verificación',
        message: `El usuario <strong>${req.user.username}</strong> ha subido sus documentos y está esperando la verificación de su cuenta.`,
        actionUrl: `${process.env.BASE_URL}/admin/verifications`
    });

        await new Notification({
            userId: req.user._id,
            type: 'admin',
            message: 'Hemos recibido tus documentos para verificación. Te notificaremos cuando el proceso haya terminado.'
        }).save();

        // ...
    res.render('verify-pending.html');
// ...
    } catch (err) {
        next(err);
    }
});


app.get('/login', (req, res) => res.render('login', { error: null }));
app.post('/login', loginLimiter, passport.authenticate('local', {
    successRedirect: '/campaigns',
    failureRedirect: '/login',
}));

app.get('/logout', (req, res, next) => {
    req.logout((err) => {
        if (err) return next(err);
        req.session.destroy(() => res.redirect('/'));
    });
});

app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
app.get('/auth/google/callback', passport.authenticate('google', { failureRedirect: '/login' }), (req, res) => {
    res.redirect('/campaigns');
});


// =============================================
//               FIN DE LA PARTE 1
// =============================================

// =... (pegar debajo del código anterior)

// =============================================
//               SERVER.JS - PARTE 2 DE 4
//          (ADAPTADO PARA DONA PARAGUAY)
// =============================================

// =============================================
// RUTAS DE PERFIL Y PÁGINAS DE USUARIO
// =============================================
app.get('/profile', requireAuth, (req, res) => res.redirect(`/user/${req.user.username}`));

// REEMPLAZA TODA LA FUNCIÓN app.get('/user/:username', ...) CON ESTE CÓDIGO
app.get('/user/:username', async (req, res, next) => {
    try {
        const userProfile = await User.findOne({ username: req.params.username.toLowerCase() });
        if (!userProfile || userProfile.isBanned) {
            return res.status(404).render('error.html', { message: 'Usuario no encontrado.' });
        }

        const isOwner = req.user && req.user._id.equals(userProfile._id);

        const campaignQuery = { userId: userProfile._id };
        // Si no es el dueño, solo mostrar campañas aprobadas
        if (!isOwner) {
            campaignQuery.status = 'approved';
        }
        const campaigns = await Campaign.find(campaignQuery).sort({ createdAt: -1 });

        // Modificamos la consulta de donaciones
        let donationQuery = { userId: userProfile._id };
        // Si no es el dueño, solo mostrar donaciones aprobadas
        if (!isOwner) {
            donationQuery.status = 'Aprobado';
        }
        
        const donations = await ManualDonation.find(donationQuery)
            .populate('campaignId', 'title _id')
            .sort({ createdAt: -1 });
        
        // El total donado público siempre se calcula sobre las donaciones aprobadas
        const totalDonated = donations
            .filter(d => d.status === 'Aprobado')
            .reduce((sum, d) => sum + (Number(d.campaignAmount) || 0), 0);
        
        let userDonations = [];
        // Mostrar donaciones si la privacidad lo permite o si es el dueño del perfil
        if (userProfile.privacySettings.showDonations || isOwner) {
            userDonations = donations;
        }

        const isFollowing = req.user ? req.user.following.some(id => id.equals(userProfile._id)) : false;
        
        // Determinar qué vista renderizar
        const viewToRender = isOwner ? 'profile.html' : 'user-profile.html';

        res.render(viewToRender, {
            userProfile,
            campaigns,
            userDonations, // Esta variable ahora contiene las donaciones correctas a mostrar
            totalDonated, // Este es el total público (solo aprobado)
            isFollowing,
            pageTitle: `Perfil de ${userProfile.username}`,
            pageDescription: `Campañas y actividad de ${userProfile.username}.`
        });
    } catch (err) {
        next(err);
    }
});

app.get('/notifications', requireAuth, async (req, res, next) => {
    try {
        const notifications = await Notification.find({ userId: req.user._id })
            .populate('actorId', 'username profilePic')
            .populate('campaignId', 'title')
            .sort({ createdAt: -1 });
        await Notification.updateMany({ userId: req.user._id, isRead: false }, { $set: { isRead: true } });
        res.render('notifications', { notifications });
    } catch (err) { next(err); }
});


// =============================================
// RUTAS DE CAMPAÑAS
// =============================================
app.get('/campaigns', async (req, res, next) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const itemsPerPage = 12;
        let query = { status: 'approved' };
        const { q, category, location } = req.query;

        if (q) {
            const searchRegex = { $regex: q, $options: 'i' };
            const matchingUsers = await User.find({ username: searchRegex }).select('_id');
            query.$or = [
                { title: searchRegex },
                { description: searchRegex },
                { userId: { $in: matchingUsers.map(u => u._id) } }
            ];
        }
        // Lógica Avanzada de Filtros
        if (category) {
            // ¿Es una categoría padre (Grupo)?
            if (CATEGORY_GROUPS[category]) {
                // Si es grupo, busca CUALQUIERA de las subcategorías de ese grupo
                query.category = { $in: CATEGORY_GROUPS[category] };
            } else {
                // Si es una subcategoría específica, busca exacto
                query.category = category;
            }
        }
        if (location) query.location = location;

        const totalCampaigns = await Campaign.countDocuments(query);
        const totalPages = Math.ceil(totalCampaigns / itemsPerPage);
        const campaigns = await Campaign.find(query)
            .populate('userId', 'username profilePic isVerified')
            .sort({ createdAt: -1 })
            .skip((page - 1) * itemsPerPage)
            .limit(itemsPerPage);

        const activeSponsors = await Sponsor.find({ status: 'active', expiresAt: { $gt: new Date() } }).sort({ createdAt: 1 });

        // Ranking de donantes (Opcional mostrarlo aquí también o solo en home)
        const topDonors = await ManualDonation.aggregate([
            { $match: { status: 'Aprobado' } },
            { $group: { _id: "$userId", totalDonated: { $sum: "$campaignAmount" } } },
            { $sort: { totalDonated: -1 } },
            { $limit: 5 },
            { $lookup: { from: "users", localField: "_id", foreignField: "_id", as: "user" } },
            { $unwind: "$user" },
            { $project: { username: "$user.username", profilePic: "$user.profilePic", totalDonated: 1 } }
        ]);

        // Renderizamos la vista dedicada 'campaigns.html'
        res.render('campaigns', {
            results: campaigns,
            currentPage: page, 
            totalPages, 
            query: req.query,
            activeSponsors,
            topDonors,
            pageTitle: 'Explorar Campañas - Dona Paraguay',
            pageDescription: 'Busca y apoya las causas que más te importan.'
        });
    } catch (err) {
        next(err);
    }
});


// =============================================
// RUTAS API PARA PAGINACIÓN (NUEVO)
// =============================================

const ITEMS_PER_PAGE = 10; // Define cuántos items cargar por página

// API para comentarios paginados
app.get('/api/campaign/:id/comments', async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const skip = (page - 1) * ITEMS_PER_PAGE;
        const campaignId = req.params.id;

        const items = await Comment.find({ campaignId })
            .populate('userId', 'username profilePic')
            .sort({ createdAt: -1 })
            .skip(skip)
            .limit(ITEMS_PER_PAGE);
        
        const totalItems = await Comment.countDocuments({ campaignId });
        res.json({ items, hasMore: (skip + items.length) < totalItems });
    } catch (error) { res.status(500).json({ error: 'Error al cargar comentarios' }); }
});

// API para donaciones paginadas
app.get('/api/campaign/:id/donations', async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const skip = (page - 1) * ITEMS_PER_PAGE;
        const campaignId = req.params.id;

        const items = await ManualDonation.find({ campaignId, status: 'Aprobado' })
            .populate('userId', 'username profilePic')
            .sort({ createdAt: -1 })
            .skip(skip)
            .limit(ITEMS_PER_PAGE);
            
        const totalItems = await ManualDonation.countDocuments({ campaignId, status: 'Aprobado' });
        res.json({ items, hasMore: (skip + items.length) < totalItems });
    } catch (error) { res.status(500).json({ error: 'Error al cargar donaciones' }); }
});

// API para actualizaciones paginadas
app.get('/api/campaign/:id/updates', async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const skip = (page - 1) * ITEMS_PER_PAGE;
        const campaignId = req.params.id;
        
        const items = await Update.find({ campaignId })
            .sort({ createdAt: -1 })
            .skip(skip)
            .limit(ITEMS_PER_PAGE);

        const totalItems = await Update.countDocuments({ campaignId });
        res.json({ items, hasMore: (skip + items.length) < totalItems });
    } catch (error) { res.status(500).json({ error: 'Error al cargar actualizaciones' }); }
});


app.get('/new-campaign', requireAuth, async (req, res, next) => { // Añadimos async y next
    try {
        // Si el usuario ya está verificado, siempre puede crear nuevas campañas.
        if (req.user.isVerified) {
            return res.render('new-campaign');
        }

        // Si NO está verificado, buscamos si ya tiene una campaña pendiente de verificación.
        const existingPendingVerification = await Campaign.findOne({ 
            userId: req.user._id, 
            status: 'pending_verification' 
        });

        // Si ya tiene una esperando verificación, lo mandamos a verificar.
        if (existingPendingVerification) {
            // Podríamos añadir un mensaje flash aquí si usaras connect-flash
            // req.flash('info', 'Ya tienes una campaña esperando verificación. Por favor, verifica tu identidad para continuar.');
            return res.redirect('/verify-account?reason=existing_pending'); 
        }

        // Si no está verificado Y NO tiene campañas pendientes de verificación, le mostramos el formulario.
        res.render('new-campaign');

    } catch (err) {
        next(err); // Manejo de errores
    }
});

app.post('/new-campaign', requireAuth, upload.array('files', 10), async (req, res, next) => {
    try {
        const { title, description, goalAmount, category, location } = req.body;
        
        // Validaciones básicas
        if (!req.files || req.files.length === 0) throw new Error("Debes subir al menos una imagen o video.");
        if (!title || !goalAmount || !category || !location) throw new Error("Todos los campos son obligatorios.");

        const isVerified = req.user.isVerified;
        
        // --- CAMBIO CLAVE: Publicación directa para verificados ---
        const newCampaign = new Campaign({
            userId: req.user._id,
            title: purify.sanitize(title),
            description: purify.sanitize(description),
            files: req.files.map(f => f.path),
            goalAmount: parseFloat(goalAmount.replace(/\./g, '')), // Asegura limpiar puntos de miles si vienen
            category,
            location,
            status: isVerified ? 'approved' : 'pending_verification' 
        });

        await newCampaign.save();

        if (isVerified) {
            // Notificar al admin solo como aviso (Vigilancia)
            await sendAdminNotificationEmail({
                subject: '🚀 Nueva Campaña Publicada Automáticamente',
                message: `El usuario verificado <strong>${req.user.username}</strong> publicó: <strong>"${newCampaign.title}"</strong>.<br><a href="${process.env.BASE_URL}/campaign/${newCampaign._id}">Revisar ahora</a>`,
                actionUrl: `${process.env.BASE_URL}/campaign/${newCampaign._id}`
            });
            
            // Redirigir con parámetro ?new=true para mostrar el modal de compartir
            res.redirect(`/campaign/${newCampaign._id}?new=true`);
        } else {
            // Si no está verificado, mandarlo a verificar
            res.redirect('/verify-account?from=new-campaign');
        }

    } catch (err) {
        // Si falla, renderizar de nuevo (puedes mejorar esto luego pasando el error)
        res.status(400).render('error', { message: err.message });
    }
});

// REEMPLAZA LA RUTA app.get('/campaign/:id', ...) COMPLETA CON ESTO:
app.get('/campaign/:id', async (req, res, next) => {
    try {
        const campaign = await Campaign.findByIdAndUpdate(req.params.id, { $inc: { views: 1 } }, { new: true })
            .populate({ path: 'userId', match: { isBanned: { $ne: true } } });

        if (!campaign || !campaign.userId) {
            return res.status(404).render('error.html', { message: 'Esta campaña no está disponible.' });
        }

        const isOwner = req.user && req.user._id.equals(campaign.userId._id);
        const isAdmin = req.user && req.user.role === 'Admin';

        if (campaign.status !== 'approved' && !isOwner && !isAdmin) {
             return res.status(403).render('error.html', { message: 'Esta campaña aún no ha sido aprobada.' });
        }

        campaign.description = purify.sanitize(campaign.description, { USE_PROFILES: { html: true } });

        // Y reemplázala por esta (cambiando 3 por 5):
const recommendedCampaigns = await Campaign.find({
    category: campaign.category, status: 'approved', _id: { $ne: campaign._id }
}).sort({ views: -1 }).limit(5).populate('userId', 'username profilePic isVerified');

        const donations = await ManualDonation.find({ campaignId: campaign._id, status: 'Aprobado' })
            .populate('userId', 'username profilePic')
            .sort({ createdAt: -1 })
            .limit(ITEMS_PER_PAGE);
        const totalDonations = await ManualDonation.countDocuments({ campaignId: campaign._id, status: 'Aprobado' });

        const updates = await Update.find({ campaignId: campaign._id }).sort({ createdAt: -1 }).limit(ITEMS_PER_PAGE);
        const totalUpdates = await Update.countDocuments({ campaignId: campaign._id });

        // --- LÓGICA DE BÚSQUEDA DE COMENTARIOS CORREGIDA Y ROBUSTA ---
        const allComments = await Comment.find({ campaignId: campaign._id })
            .populate('userId', 'username profilePic')
            .sort({ createdAt: 'asc' });

        const commentMap = {};
        allComments.forEach(comment => {
            comment.replies = [];
            commentMap[comment._id] = comment;
        });

        const nestedComments = [];
        allComments.forEach(comment => {
            if (comment.parentCommentId && commentMap[comment.parentCommentId]) {
                commentMap[comment.parentCommentId].replies.push(comment);
            } else {
                nestedComments.push(comment);
            }
        });

        nestedComments.sort((a, b) => b.createdAt - a.createdAt);
        const totalComments = await Comment.countDocuments({ campaignId: campaign._id });
        
        const userHasLiked = req.user ? campaign.likes.some(like => like.equals(req.user._id)) : false;
        
        const activeSponsors = await Sponsor.find({ status: 'active', expiresAt: { $gt: new Date() } }).sort({ createdAt: 1 });

        res.render('campaign-detail.html', {
            campaign, 
            isOwner,
            donations,
            totalDonations,
            updates,
            totalUpdates,
            comments: nestedComments,
            totalComments,
            recommendedCampaigns,
            userHasLiked,
            isAdmin,
            pageTitle: `${campaign.title} - Dona Paraguay`,
            pageDescription: campaign.description.replace(/<[^>]*>?/gm, '').slice(0, 150),
            activeSponsors
        });
    } catch (err) {
        next(err);
    }
});

app.get('/campaign/:id/edit', requireAuth, async (req, res, next) => {
    try {
        const campaign = await Campaign.findById(req.params.id);
        if (!campaign || !campaign.userId.equals(req.user._id)) {
            return res.status(403).render('error', { message: 'No tienes permiso para editar esta campaña.' });
        }
        res.render('edit-campaign', { campaign });
    } catch (err) { next(err); }
});

app.post('/campaign/:id/edit', requireAuth, async (req, res, next) => {
    try {
        const campaign = await Campaign.findById(req.params.id);
        if (!campaign || !campaign.userId.equals(req.user._id)) {
             return res.status(403).render('error', { message: 'No tienes permiso para editar esta campaña.' });
        }
        const { title, description, goalAmount, category, location, tags } = req.body;
        await Campaign.findByIdAndUpdate(req.params.id, {
            title: purify.sanitize(title),
            description: purify.sanitize(description),
            goalAmount, category, location,
            tags: tags ? tags.split(',').map(t => purify.sanitize(t.trim())) : []
        });
        res.redirect(`/campaign/${req.params.id}`);
    } catch (err) { next(err); }
});

app.post('/campaign/:id/delete', requireAuth, async (req, res, next) => {
    try {
        const campaign = await Campaign.findById(req.params.id);
        
        if (!campaign) {
            return res.status(404).json({ success: false, message: "Campaña no encontrada." });
        }

        const isOwner = campaign.userId.equals(req.user._id);
        const isAdmin = req.user.role === 'Admin';

        if (!isOwner && !isAdmin) {
            return res.status(403).json({ success: false, message: "No tienes permiso para eliminar esto." });
        }

        // --- CORRECCIÓN DE CLOUDINARY ---
        for (const fileUrl of campaign.files) {
            const publicId = getPublicId(fileUrl);
            if (publicId) {
                // Determinamos si es video o imagen antes de borrar
                // Buscamos extensiones de video o la palabra '/video/' en la URL de Cloudinary
                const isVideo = fileUrl.match(/\.(mp4|mov|avi|mkv|webm)$/i) || fileUrl.includes('/video/');
                const resourceType = isVideo ? 'video' : 'image';

                await cloudinary.uploader.destroy(publicId, { resource_type: resourceType })
                    .catch(err => console.error("Fallo al eliminar de Cloudinary:", err));
            }
        }
        // -------------------------------

        await Campaign.findByIdAndDelete(req.params.id);

        // Redirigir al panel de control
        const redirectUrl = isAdmin ? '/admin/campaigns' : '/settings/dashboard'; 
        res.json({ success: true, redirectUrl });
    } catch (err) { 
        console.error("Error al eliminar campaña:", err);
        next(err); 
    }
});



// REEMPLAZA LA RUTA app.post('/campaign/:id/update', ...) COMPLETA CON ESTA:
app.post('/campaign/:id/update', requireAuth, async (req, res, next) => {
    try {
        const campaign = await Campaign.findById(req.params.id);
        if (!campaign || !campaign.userId.equals(req.user._id)) {
            return res.status(403).send('No tienes permiso para hacer esto.');
        }
        
        const { content } = req.body;
        const newUpdate = new Update({
            campaignId: req.params.id,
            userId: req.user._id,
            content: purify.sanitize(content, { USE_PROFILES: { html: true } })
        });
        await newUpdate.save();

        // Si la petición es AJAX (desde el formulario), renderizamos solo el partial.
        if (req.xhr || req.headers.accept.indexOf('json') > -1) {
            const partialPath = path.join(__dirname, 'views', 'partials', 'update-partial.html');
            const html = await ejs.renderFile(partialPath, {
                update: newUpdate,
                formatDate: formatDate,
                locals: res.locals 
            });
            // Enviamos solo el HTML del nuevo item, no la página completa.
            return res.send(html);
        }

        // Si no es AJAX, redirigimos (como fallback).
        res.redirect(`/campaign/${req.params.id}`);
    } catch (err) {
        console.error("Error al publicar actualización:", err);
        if (req.xhr || req.headers.accept.indexOf('json') > -1) {
            return res.status(500).send('No se pudo publicar la actualización.');
        }
        next(err);
    }
});

// REEMPLAZA LA RUTA app.post('/campaign/:id/comment', ...) COMPLETA CON ESTA:
app.post('/campaign/:id/comment', requireAuth, async (req, res, next) => {
    try {
        const { text, parentCommentId } = req.body;
        const campaignId = req.params.id;
        const sanitizedText = purify.sanitize(text);
        let rootCommentId = parentCommentId; // Asumimos que el padre es el comentario raíz inicialmente.

        const newCommentData = {
            campaignId,
            userId: req.user._id,
            text: sanitizedText
        };

        if (parentCommentId) {
            const parentComment = await Comment.findById(parentCommentId).populate('userId', 'username');
            if (parentComment) {
                // Si el comentario al que respondo ya es una respuesta, busco a su verdadero padre (el comentario raíz).
                if (parentComment.parentCommentId) {
                    rootCommentId = parentComment.parentCommentId;
                }
                // Añadimos una mención al usuario que estamos respondiendo para dar contexto.
                newCommentData.text = `<span class="mention">@${parentComment.userId.username}</span> ${sanitizedText}`;
                newCommentData.parentCommentId = rootCommentId;
            }
        }
        
        const newComment = new Comment(newCommentData);
        await newComment.save();
        
        // Siempre añadimos la nueva respuesta al comentario raíz.
        if (rootCommentId) {
            await Comment.findByIdAndUpdate(rootCommentId, { $push: { replies: newComment._id } });
        }

        if (req.xhr || req.headers.accept.indexOf('json') > -1) {
            const populatedComment = await Comment.findById(newComment._id).populate('userId', 'username profilePic');
            const partialToRender = 'partials/reply-partial.html'; // Usamos siempre el partial de respuesta
            const partialPath = path.join(__dirname, 'views', partialToRender);

            const html = await ejs.renderFile(partialPath, { 
                comment: populatedComment,
                campaign: { _id: campaignId },
                currentUser: req.user,
                formatDate: formatDate,
                locals: res.locals,
                rootCommentId: rootCommentId // Pasamos el ID del comentario raíz a la plantilla
            });
            return res.send(html);
        }
        
        res.redirect(`/campaign/${campaignId}`);
    } catch (err) {
        console.error("Error al publicar comentario:", err);
        if (req.xhr || req.headers.accept.indexOf('json') > -1) {
            return res.status(500).send('No se pudo publicar el comentario.');
        }
        next(err);
    }
});


// =============================================
// RUTAS PARA LIKES Y FOLLOWS (NUEVO)
// =============================================

// Ruta para dar/quitar like a una campaña
app.post('/campaign/:id/like', requireAuth, async (req, res, next) => {
    try {
        const campaign = await Campaign.findById(req.params.id);
        if (!campaign) return res.status(404).json({ success: false });

        const userId = req.user._id;
        const userIndex = campaign.likes.indexOf(userId);

        if (userIndex > -1) {
            campaign.likes.splice(userIndex, 1); // Quitar like
        } else {
            campaign.likes.push(userId); // Dar like
        }
        await campaign.save();
        res.json({ success: true, likes: campaign.likes.length, liked: userIndex === -1 });
    } catch (err) {
        res.status(500).json({ success: false });
    }
});

// Ruta para seguir/dejar de seguir a un usuario
app.post('/user/:id/follow', requireAuth, async (req, res, next) => {
    try {
        const userToFollow = await User.findById(req.params.id);
        const currentUser = await User.findById(req.user._id);

        if (!userToFollow || !currentUser || currentUser.equals(userToFollow)) {
            return res.status(400).json({ success: false });
        }

        const followingIndex = currentUser.following.indexOf(userToFollow._id);
        const followerIndex = userToFollow.followers.indexOf(currentUser._id);

        if (followingIndex > -1) { // Si ya lo sigue, dejar de seguir
            currentUser.following.splice(followingIndex, 1);
            if (followerIndex > -1) userToFollow.followers.splice(followerIndex, 1);
        } else { // Si no lo sigue, seguir
            currentUser.following.push(userToFollow._id);
            if (followerIndex === -1) userToFollow.followers.push(currentUser._id);
        }

        await currentUser.save();
        await userToFollow.save();
        res.json({ success: true, followers: userToFollow.followers.length, following: followingIndex === -1 });

    } catch (err) {
        res.status(500).json({ success: false });
    }
});

// =============================================
// RUTAS DE DONACIÓN MANUAL
// =============================================

// Muestra el formulario para donar a una campaña específica
app.get('/campaign/:id/donate', requireAuth, async (req, res, next) => {
    try {
        const campaign = await Campaign.findById(req.params.id).populate('userId');
        if (!campaign || campaign.status !== 'approved') {
            return res.status(404).render('error', { message: 'No se puede donar a esta campaña en este momento.' });
        }
        // Corregido: Apunta a la vista correcta en la carpeta 'views'
        res.render('donate-form', { campaign });
    } catch (err) {
        next(err);
    }
});

// Procesa la subida del comprobante de donación
app.post('/campaign/:id/donate', requireAuth, upload.single('proof'), async (req, res, next) => {
    try {
        const campaignId = req.params.id;
        const { amount, campaignAmount, platformTip, comment } = req.body; // <-- comment AÑADIDO

        if (!req.file) throw new Error("Debes subir una imagen del comprobante de donación.");
        if (!amount || !campaignAmount || parseInt(campaignAmount) < 5000) {
            throw new Error("El monto mínimo de donación para la campaña es de 5.000 Gs.");
        }

        const newDonation = new ManualDonation({
            userId: req.user._id,
            campaignId: campaignId,
            amount: parseInt(amount),
            campaignAmount: parseInt(campaignAmount),
            platformTip: parseInt(platformTip || 0),
            proofImageUrl: req.file.path,
            comment: purify.sanitize(comment), // <-- Guardar el comentario sanitizado
            status: 'Pendiente'
        });
        await newDonation.save();

        const campaign = await Campaign.findById(campaignId);
        if (campaign) {
            await new Notification({
                userId: campaign.userId, actorId: req.user._id, type: 'admin',
                message: `ha enviado una donación de ${parseInt(amount).toLocaleString('es-PY')} Gs. para tu campaña "${campaign.title}". Está pendiente de aprobación.`
            }).save();
        }


           await sendAdminNotificationEmail({
        subject: 'Nueva Donación Pendiente',
        message: `El usuario <strong>${req.user.username}</strong> ha enviado una donación de <strong>${parseInt(amount).toLocaleString('es-PY')} Gs.</strong> para la campaña <strong>"${campaign.title}"</strong>.`,
        actionUrl: `${process.env.BASE_URL}/admin/donations`
    });

        res.render('donation-success.html', { campaign: campaign });
    } catch (err) {
        next(err);
    }
});




// --- INICIO: RUTAS PARA EDITAR Y ELIMINAR ACTUALIZACIONES ---

// Muestra el formulario para editar una actualización
app.get('/campaign/:campaignId/update/:updateId/edit', requireAuth, async (req, res, next) => {
    try {
        const { campaignId, updateId } = req.params;
        const campaign = await Campaign.findById(campaignId);
        const update = await Update.findById(updateId);

        // Asegurarse que el usuario es el dueño de la campaña
        if (!campaign || !campaign.userId.equals(req.user._id) || !update || !update.campaignId.equals(campaign._id)) {
            return res.status(403).render('error', { message: 'No tienes permiso para editar esto.' });
        }

        res.render('edit-update', { campaign, update });
    } catch (err) {
        next(err);
    }
});

// Procesa la edición de una actualización
app.post('/campaign/:campaignId/update/:updateId/edit', requireAuth, async (req, res, next) => {
    try {
        const { campaignId, updateId } = req.params;
        const campaign = await Campaign.findById(campaignId);

        if (!campaign || !campaign.userId.equals(req.user._id)) {
            return res.status(403).send('No autorizado.');
        }

        const sanitizedContent = purify.sanitize(req.body.content, { USE_PROFILES: { html: true } });
        await Update.findOneAndUpdate(
            { _id: updateId, campaignId: campaignId },
            { content: sanitizedContent }
        );

        res.redirect(`/campaign/${campaignId}`);
    } catch (err) {
        next(err);
    }
});

// Elimina una actualización
app.post('/campaign/:id/update/:updateId/delete', requireAuth, async (req, res, next) => {
    try {
        const campaign = await Campaign.findById(req.params.id);
        if (!campaign || !campaign.userId.equals(req.user._id)) {
            return res.status(403).json({ success: false, message: 'No tienes permiso.' });
        }
        await Update.findOneAndDelete({ _id: req.params.updateId, campaignId: req.params.id });
        res.json({ success: true });
    } catch (err) {
        next(err);
    }
});

// --- FIN: RUTAS PARA EDITAR Y ELIMINAR ACTUALIZACIONES ---


// =============================================
// RUTAS DEL PANEL DE CONFIGURACIÓN DEL USUARIO/ORGANIZADOR
// =============================================

app.get('/settings/dashboard', requireAuth, async (req, res, next) => {
    try {
        const campaigns = await Campaign.find({ userId: req.user._id }).sort({ createdAt: -1 });
        const totalRaised = campaigns.reduce((sum, camp) => sum + camp.amountRaised, 0);
        const totalViews = campaigns.reduce((sum, camp) => sum + camp.views, 0);

        // Contar donantes únicos
        const uniqueDonors = await ManualDonation.distinct('userId', {
            campaignId: { $in: campaigns.map(c => c._id) },
            status: 'Aprobado'
        });

        res.render('settings/dashboard', {
            campaigns,
            totalRaised,
            totalViews,
            uniqueDonorsCount: uniqueDonors.length
        });
    } catch (err) {
        next(err);
    }
});

app.get('/settings/profile', requireAuth, (req, res) => {
    res.render('settings/profile');
});

app.post('/settings/profile', requireAuth, upload.single('profilePic'), async (req, res, next) => {
    try {
        const { username, bio, phone, location, socialLinks } = req.body;
        const userToUpdate = await User.findById(req.user._id);

        if (req.file) {
            if (userToUpdate.profilePic && !userToUpdate.profilePic.includes('default')) {
                const publicId = getPublicId(userToUpdate.profilePic);
                if (publicId) await cloudinary.uploader.destroy(publicId);
            }
        }
        
        const updateData = {
            username: purify.sanitize(username),
            bio: purify.sanitize(bio),
            phone,
            location,
            socialLinks: {
                facebook: socialLinks.facebook,
                instagram: socialLinks.instagram,
                twitter: socialLinks.twitter
            }
        };

        if (req.file) updateData.profilePic = req.file.path;
        
        await User.findByIdAndUpdate(req.user._id, updateData, { new: true });

        res.redirect('/settings/profile');

    } catch (err) { 
        next(err); 
    }
});

app.get('/settings/payouts', requireAuth, async (req, res, next) => {
    try {
        // Un organizador solo puede retirar fondos de sus propias campañas
        const campaigns = await Campaign.find({ userId: req.user._id, status: 'approved' });
        const withdrawals = await Withdrawal.find({ userId: req.user._id }).sort({ createdAt: -1 });

        res.render('settings/payouts', { campaigns, withdrawals });
    } catch (err) {
        next(err);
    }
});

// donaparaguay/server.js: (Ruta /settings/payouts)

app.post('/settings/payouts', requireAuth, async (req, res, next) => {
    const dbSession = await mongoose.startSession();
    try {
        await dbSession.withTransaction(async (session) => {
            const { amount, method, campaignId, fullName, ci, bankName, accountNumber, phone, alias } = req.body;
            const user = req.user;
            const amountNum = parseInt(amount);

            const campaign = await Campaign.findOne({ _id: campaignId, userId: user._id }).session(session);
            if (!campaign) throw new Error("Campaña no encontrada o no te pertenece.");
            if (isNaN(amountNum) || amountNum < 30000) throw new Error(`El monto mínimo de retiro es 30.000 Gs.`);
            if (campaign.amountRaised < amountNum) throw new Error("No tienes suficientes fondos recaudados en esta campaña para retirar ese monto.");

            let details = {};
            if (method === 'transferencia') details = { fullName, ci, bankName, accountNumber, alias };
            else if (method === 'giro') details = { fullName, ci, phone };
            else throw new Error("Método de retiro no válido.");

            // FIX: Se elimina la deducción de fondos en la solicitud.
            // Los fondos se descontarán correctamente al ser aprobados por el administrador.
            // REMOVED: campaign.amountRaised -= amountNum;
            // REMOVED: await campaign.save({ session });

            // Crear el registro de retiro (aún en estado 'Pendiente')
            await new Withdrawal({
                userId: user._id,
                campaignId: campaign._id,
                amount: amountNum,
                method,
                details,
                status: 'Pendiente'
            }).save({ session });
        });
        res.redirect('/settings/payouts');
    } catch (err) {
        next(err);
    } finally {
        await dbSession.endSession();
    }
});


// Enviar código para eliminar cuenta
app.post('/settings/send-deletion-code', requireAuth, async (req, res, next) => {
    try {
        const user = await User.findById(req.user._id);

        // --- INICIO DE LA CORRECCIÓN ---
        // Si el usuario no tiene un secreto de verificación, créalo ahora.
        if (!user.verificationSecret) {
            const secret = speakeasy.generateSecret({ length: 20 });
            user.verificationSecret = secret.base32;
        }
        // --- FIN DE LA CORRECCIÓN ---

        const code = speakeasy.totp({ secret: user.verificationSecret, encoding: 'base32', step: 300 });

        user.verificationCode = code;
        user.verificationCodeExpires = Date.now() + 300000; // 5 minutos
        await user.save(); // Guarda el nuevo secreto (si fue creado) y el código.

        await transporter.sendMail({
            from: `"Soporte Dona Paraguay" <${process.env.EMAIL_USER}>`,
            to: user.email, subject: `Tu código para ELIMINAR tu cuenta es ${code}`,
            html: `<h2>Confirmación para Eliminar Cuenta</h2><p>Usa el siguiente código para confirmar la eliminación <strong>permanente</strong> de tu cuenta: <strong>${code}</strong>. Es válido por 5 minutos.</p>`
        });
        res.status(200).json({ success: true, message: 'Código enviado a tu correo.' });
    } catch (err) {
        console.error("Error al enviar código de eliminación:", err); // Añadido para mejor depuración
        res.status(500).json({ success: false, message: 'Error interno del servidor.' });
    }
});



// --- NUEVA RUTA PARA PRIVACIDAD ---
app.post('/settings/privacy', requireAuth, async (req, res, next) => {
    try {
        const user = await User.findById(req.user._id);
        const showDonations = req.body.showDonations === 'on'; // Checkbox envía 'on' si está marcado
        user.privacySettings.showDonations = showDonations;
        await user.save();
        req.session.success = 'Configuración de privacidad guardada.';
        res.redirect('/settings/security');
    } catch (err) {
        req.session.error = err.message;
        res.redirect('/settings/security');
    }
});


app.get('/my-donations', requireAuth, async (req, res, next) => {
    try {
        const donations = await ManualDonation.find({ userId: req.user._id })
            .populate('campaignId', 'title _id')
            .sort({ createdAt: -1 });
        res.render('my-donations', { donations });
    } catch (err) {
        next(err);
    }
});





// =============================================
//               FIN DE LA PARTE 2
// =============================================


// =... (pegar debajo del código anterior)

// =============================================
//               SERVER.JS - PARTE 3 DE 4
//          (ADAPTADO PARA DONA PARAGUAY)
// =============================================


// =============================================
// RUTAS DEL PANEL DE ADMINISTRACIÓN
// =============================================
app.get('/admin', requireAdmin, (req, res) => res.redirect('/admin/dashboard'));

// donaparaguay/server.js

app.get('/admin/dashboard', requireAdmin, async (req, res, next) => {
    try {
        // --- INICIO DE LA MODIFICACIÓN ---
        // Calcula el umbral de tiempo para "activos en el último minuto"
        const sessionTTL_in_ms = 10 * 24 * 60 * 60 * 1000; // TTL de 10 días en milisegundos
        const activeThreshold = new Date(Date.now() + sessionTTL_in_ms - 60000); // now + TTL - 1 minuto

        const [
            totalUsers,
            activeUsers,
            totalCampaigns,
            pendingWithdrawals,
            pendingDonations,
            pendingVerifications,
            activeNowUsers // <-- NUEVA VARIABLE
        ] = await Promise.all([
            User.countDocuments(),
            User.countDocuments({ isBanned: false }),
            Campaign.countDocuments(),
            Withdrawal.countDocuments({ status: 'Pendiente' }),
            ManualDonation.countDocuments({ status: 'Pendiente' }),
            Verification.countDocuments({ status: 'pending' }),
            // Nueva consulta a la colección de sesiones de MongoDB
            mongoose.connection.db.collection('sessions').countDocuments({ expires: { $gt: activeThreshold } })
        ]);

        const stats = {
            totalUsers,
            activeUsers,
            totalCampaigns,
            pendingWithdrawals,
            pendingDonations,
            pendingVerifications,
            activeNowUsers // <-- NUEVO DATO AÑADIDO
        };
        // --- FIN DE LA MODIFICACIÓN ---
        
        res.render('admin/dashboard.html', { stats: stats, path: req.path });
    } catch (err) {
        next(err);
    }
});

// --- GESTIÓN DE USUARIOS ---
app.get('/admin/users', requireAdmin, async (req, res, next) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const itemsPerPage = 15;
        let query = {};
        if (req.query.search) {
            const regex = { $regex: req.query.search, $options: 'i' };
            query = { $or: [{ username: regex }, { email: regex }] };
        }
        const totalUsers = await User.countDocuments(query);
        const totalPages = Math.ceil(totalUsers / itemsPerPage);
        const users = await User.find(query).sort({ createdAt: -1 }).skip((page - 1) * itemsPerPage).limit(itemsPerPage);
        res.render('admin/users.html', { users, totalPages, currentPage: page, path: req.path, query: req.query });
    } catch (err) { next(err); }
});

app.get('/admin/user/:id', requireAdmin, async (req, res, next) => {
    try {
        const userId = req.params.id;
        const user = await User.findById(userId);
        if (!user) return res.redirect('/admin/users');

        const campaigns = await Campaign.find({ userId: userId }).sort({ createdAt: -1 });
        const withdrawals = await Withdrawal.find({ userId: userId }).sort({ createdAt: -1 });
        const donationsMade = await ManualDonation.find({ userId: userId }).populate('campaignId', 'title').sort({ createdAt: -1 });
        const verification = await Verification.findOne({ userId: userId });

        res.render('admin/user-detail.html', {
            user, campaigns, withdrawals, donationsMade, verification, path: req.path
        });
    } catch (err) {
        next(err);
    }
});

app.post('/admin/user/:id/toggle-ban', requireAdmin, async (req, res, next) => {
    try {
        const user = await User.findById(req.params.id);
        if (user && user.role !== 'Admin') {
            user.isBanned = !user.isBanned;
            await user.save();
            await new AuditLog({
                adminId: req.user._id, action: user.isBanned ? 'baneo_usuario' : 'desbaneo_usuario',
                targetUserId: user._id, details: `El usuario ${user.username} fue ${user.isBanned ? 'baneado' : 'desbaneado'}.`
            }).save();
        }
        res.redirect(`/admin/user/${req.params.id}`);
    } catch (err) { next(err); }
});

app.post('/admin/user/:id/toggle-verify', requireAdmin, async (req, res, next) => {
    try {
        const user = await User.findById(req.params.id);
        if (user) {
            user.isVerified = !user.isVerified;
            await user.save();
        }
        res.redirect(`/admin/user/${req.params.id}`);
    } catch (err) { next(err); }
});


// --- GESTIÓN DE CAMPAÑAS ---
app.get('/admin/campaigns', requireAdmin, async (req, res, next) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const itemsPerPage = 15;
        let query = {};
        if (req.query.search) {
            query.title = { $regex: req.query.search, $options: 'i' };
        }
        const totalCampaigns = await Campaign.countDocuments(query);
        const totalPages = Math.ceil(totalCampaigns / itemsPerPage);
        const campaigns = await Campaign.find(query).populate('userId', 'username').sort({ createdAt: -1 }).skip((page - 1) * itemsPerPage).limit(itemsPerPage);
        res.render('admin/campaigns.html', { campaigns, totalPages, currentPage: page, path: req.path, query: req.query });
    } catch (err) { next(err); }
});

// --- GESTIÓN DE DONACIONES MANUALES (NUEVA SECCIÓN CRÍTICA) ---
app.get('/admin/donations', requireAdmin, async (req, res, next) => {
    try {
        const donations = await ManualDonation.find({ status: 'Pendiente' })
            .populate('userId', 'username email')
            .populate('campaignId', 'title')
            .sort({ createdAt: 'desc' });
        res.render('admin/donations.html', { donations, path: req.path });
    } catch (err) {
        next(err);
    }
});

app.post('/admin/donation/:id/update', requireAdmin, async (req, res, next) => {
    const dbSession = await mongoose.startSession();
    try {
        await dbSession.withTransaction(async (session) => {
            const { status } = req.body;
            const donation = await ManualDonation.findById(req.params.id).session(session);
            if (!donation || donation.status !== 'Pendiente') {
                throw new Error('Donación no encontrada o ya procesada.');
            }

            const campaign = await Campaign.findById(donation.campaignId).populate('userId', 'email username').session(session);
            if (!campaign) {
                donation.status = 'Rechazado';
                await donation.save({ session });
                throw new Error('La campaña asociada a esta donación ya no existe.');
            }

            if (status === 'Aprobado') {
                const oldAmountRaised = campaign.amountRaised;
                campaign.amountRaised += donation.campaignAmount;
                const newAmountRaised = campaign.amountRaised;
                const goalAmount = campaign.goalAmount;

                donation.status = 'Aprobado';
                await awardBadges(donation.userId, donation);
                await donation.save({ session });
                
                await new Transaction({
                    type: 'donation',
                    donatorId: donation.userId,
                    organizerId: campaign.userId._id,
                    campaignId: campaign._id,
                    amount: donation.campaignAmount,
                    platformFee: donation.platformTip,
                }).save({ session });

                await new Notification({
                    userId: campaign.userId._id,
                    actorId: donation.userId,
                    type: 'donation',
                    campaignId: campaign._id,
                    message: `recibió una nueva donación de ${donation.campaignAmount.toLocaleString('es-PY')} Gs. para tu campaña "${campaign.title}".`
                }).save({ session });

                 await new Notification({
                    userId: donation.userId,
                    type: 'admin',
                    message: `Tu donación de ${donation.amount.toLocaleString('es-PY')} Gs. para la campaña "${campaign.title}" fue aprobada. ¡Gracias por tu generosidad!`
                }).save({ session });


                // --- NUEVO: Lógica de notificación por hitos con plantillas HTML ---
                const totalDonationsCount = await ManualDonation.countDocuments({ campaignId: campaign._id, status: 'Aprobado' }).session(session);
                
                const sendMilestoneEmail = async (data) => {
                    try {
                        const emailHtml = await ejs.renderFile(path.join(__dirname, 'views', 'emails', 'campaign-milestone.html'), data);
                        await transporter.sendMail({
                            from: `"Soporte Dona Paraguay" <${process.env.EMAIL_USER}>`,
                            to: campaign.userId.email,
                            subject: data.subject,
                            html: emailHtml
                        });
                    } catch (emailError) {
                        console.error(`❌ Error al enviar correo de hito (${data.subject}):`, emailError);
                    }
                };

                // Hito 1: Primera donación
                if (totalDonationsCount === 1 && !campaign.milestonesNotified.get('firstDonation')) {
                    await sendMilestoneEmail({
                        subject: '🎉 ¡Recibiste tu primera donación!',
                        title: '¡El primer paso está dado!',
                        username: campaign.userId.username,
                        message: `<p>Tu campaña <strong>"${campaign.title}"</strong> ha recibido su primera donación. ¡Este es el comienzo de algo grande!</p>`,
                        campaignUrl: `${process.env.BASE_URL}/campaign/${campaign._id}`
                    });
                    campaign.milestonesNotified.set('firstDonation', true);
                }

                // Hitos por porcentaje
                if (goalAmount > 0) {
                    const oldProgress = (oldAmountRaised / goalAmount) * 100;
                    const newProgress = (newAmountRaised / goalAmount) * 100;
                    const milestones = [10, 50, 100];

                    for (const milestone of milestones) {
                        const milestoneKey = `progress${milestone}`;
                        if (newProgress >= milestone && oldProgress < milestone && !campaign.milestonesNotified.get(milestoneKey)) {
                            let emailData = {
                                subject: `¡Tu campaña alcanzó el ${milestone}% de la meta!`,
                                title: '¡Siguen las buenas noticias!',
                                username: campaign.userId.username,
                                message: `<p>¡Vas muy bien! Tu campaña <strong>"${campaign.title}"</strong> ha alcanzado o superado el <strong>${milestone}%</strong> de su meta de recaudación.</p>`,
                                campaignUrl: `${process.env.BASE_URL}/campaign/${campaign._id}`
                            };
                            
                            if (milestone === 100) {
                                emailData.subject = `¡META ALCANZADA! Tu campaña "${campaign.title}" lo logró`;
                                emailData.title = '¡Lo lograron!';
                                emailData.message = `<p>¡Felicidades! Tu campaña <strong>"${campaign.title}"</strong> ha alcanzado el 100% de su meta. Gracias a ti y a todos los donantes por hacerlo posible.</p>`;
                                campaign.status = 'completed';
                            }
                            
                            await sendMilestoneEmail(emailData);
                            campaign.milestonesNotified.set(milestoneKey, true);
                        }
                    }
                }
                // --- FIN DEL NUEVO CÓDIGO ---

                await campaign.save({ session });

            } else if (status === 'Rechazado') {
                donation.status = 'Rechazado';
                await donation.save({ session });
                await new Notification({
                    userId: donation.userId,
                    type: 'admin',
                    message: `Tu donación para la campaña "${campaign.title}" fue rechazada. Contacta a soporte si crees que es un error.`
                }).save({ session });
            }
        });
        res.redirect('/admin/donations');
    } catch (err) {
        next(err);
    } finally {
        await dbSession.endSession();
    }
});


// --- GESTIÓN DE RETIROS ---
app.get('/admin/withdrawals', requireAdmin, async (req, res, next) => {
    try {
        const withdrawals = await Withdrawal.find()
            .populate('userId', 'username email')
            .populate('campaignId', 'title')
            .sort({ createdAt: -1 });
        res.render('admin/withdrawals.html', { withdrawals, path: req.path });
    } catch (err) { next(err); }
});

// donaparaguay/server.js: (Ruta /admin/withdrawal/:id/update)

app.post('/admin/withdrawal/:id/update', requireAdmin, async (req, res, next) => {
    const dbSession = await mongoose.startSession();
    try {
        await dbSession.withTransaction(async (session) => {
            const { status } = req.body;
            const withdrawal = await Withdrawal.findById(req.params.id).session(session);
            if (!withdrawal) throw new Error('Solicitud no encontrada');
            if (withdrawal.status !== 'Pendiente') throw new Error('El estado de retiro ya fue actualizado.');

            if (status === 'Procesado') {
                const config = await SiteConfig.findOne({ configKey: 'main_config' }).session(session);
                const feeRate = config.platformFeeRate || 0.10;
                
                const grossAmount = withdrawal.amount;
                const feeAmount = Math.round(grossAmount * feeRate);
                const netAmount = grossAmount - feeAmount; // El monto que recibe el organizador

                // 1. DEDUCCIÓN FINAL: Descontar el monto total solicitado (bruto) de la campaña.
                const campaign = await Campaign.findById(withdrawal.campaignId).populate('userId').session(session);
                if (!campaign) throw new Error('Campaña asociada no encontrada.');
                
                campaign.amountRaised -= grossAmount; // Se resta el 100% que se procesó
                await campaign.save({ session });

                // 2. REGISTROS DE TRANSACCIÓN (Comisión y Retiro neto)
                await new Transaction({ // Registro de la comisión
                    type: 'platform_fee',
                    organizerId: campaign.userId._id,
                    campaignId: campaign._id,
                    amount: feeAmount,
                    status: 'COMPLETADO'
                }).save({ session });
                
                await new Transaction({ // Registro del retiro neto
                    type: 'withdrawal',
                    organizerId: campaign.userId._id,
                    campaignId: campaign._id,
                    amount: netAmount,
                    platformFee: feeAmount,
                    status: 'COMPLETADO'
                }).save({ session });
                
                // 3. Notificación al usuario
                await new Notification({ 
                    userId: withdrawal.userId, type: 'admin', 
                    message: `Tu retiro de ${grossAmount.toLocaleString('es-PY')} Gs. (Comisión: ${feeAmount.toLocaleString('es-PY')} Gs., Neto: ${netAmount.toLocaleString('es-PY')} Gs.) ha sido procesado.`
                }).save({ session });

            } else if (status === 'Rechazado') {
                 // No hay reversión de fondos, ya que no se dedujeron en la solicitud.
                await new Notification({ 
                    userId: withdrawal.userId, type: 'admin', 
                    message: `Tu solicitud de retiro de ${withdrawal.amount.toLocaleString('es-PY')} Gs. ha sido rechazada. Los fondos permanecen en tu campaña.`
                }).save({ session });
            }

            withdrawal.status = status;
            await withdrawal.save({ session });
        });
        res.redirect('/admin/withdrawals');
    } catch (err) { next(err); } finally { await dbSession.endSession(); }
});

// --- GESTIÓN DE VERIFICACIONES DE IDENTIDAD ---
// --- GESTIÓN DE VERIFICACIONES DE IDENTIDAD ---
app.get('/admin/verifications', requireAdmin, async (req, res, next) => {
    try {
        const pendingVerifications = await Verification.find({ status: 'pending' }).populate('userId', 'username');
        res.render('admin/verifications.html', { verifications: pendingVerifications, path: req.path });
    } catch (err) { next(err); }
});

app.post('/admin/verification/:id/approve', requireAdmin, async (req, res, next) => {
    try {
        const verification = await Verification.findById(req.params.id).populate('userId', 'email username');
        if (!verification || !verification.userId) throw new Error('Solicitud no encontrada o usuario no válido.');

        await User.findByIdAndUpdate(verification.userId._id, { isVerified: true });
        verification.status = 'approved';
        await verification.save();

// --- AÑADE ESTA LÍNEA ---
        // Busca todas las campañas del usuario que estaban esperando verificación y pásalas a "pendiente".
        await Campaign.updateMany({ userId: verification.userId._id, status: 'pending_verification' }, { $set: { status: 'pending' } });

        await new Notification({ userId: verification.userId._id, type: 'admin', message: '¡Felicidades! Tu cuenta ha sido verificada y ahora puedes crear campañas.' }).save();
        // --- NUEVO: Enviar correo de bienvenida con plantilla HTML ---
        try {
            const emailHtml = await ejs.renderFile(path.join(__dirname, 'views', 'emails', 'verification-approved.html'), {
                username: verification.userId.username,
                newCampaignUrl: `${process.env.BASE_URL}/new-campaign`
            });

            await transporter.sendMail({
                from: `"Soporte Dona Paraguay" <${process.env.EMAIL_USER}>`,
                to: verification.userId.email,
                subject: '✅ ¡Tu cuenta en Dona Paraguay ha sido verificada!',
                html: emailHtml
            });
        } catch (emailError) {
            console.error('❌ Error al enviar el correo de verificación:', emailError);
        }
        // --- FIN DEL NUEVO CÓDIGO ---

        res.redirect('/admin/verifications');
    } catch (err) { next(err); }
});

app.post('/admin/verification/:id/reject', requireAdmin, async (req, res, next) => {
    try {
        const { reason } = req.body;
        const verification = await Verification.findById(req.params.id);
        if (verification) {
            verification.status = 'rejected';
            verification.rejectionReason = reason || 'Los documentos no son claros o no cumplen los requisitos.';
            await verification.save();
            await User.findByIdAndUpdate(verification.userId, { isVerified: false });
            await new Notification({ userId: verification.userId, type: 'admin', message: `Tu solicitud de verificación fue rechazada. Motivo: ${verification.rejectionReason}` }).save();
        }
        res.redirect('/admin/verifications');
    } catch (err) { next(err); }
});



// --- RUTAS DE CONFIGURACIÓN DEL ADMIN ---
app.get('/admin/settings', requireAdmin, (req, res, next) => {
    res.render('admin/settings.html', { 
        path: req.path,
        success: req.session.success,
        error: req.session.error
    });
    delete req.session.success;
    delete req.session.error;
});

app.post('/admin/settings', requireAdmin, async (req, res, next) => {
    try {
        const { donationDetails } = req.body;
        const sanitizedDetails = purify.sanitize(donationDetails, {
            ALLOWED_TAGS: ['strong', 'b', 'i', 'em', 'br', 'p', 'ul', 'li'],
        });

        await SiteConfig.findOneAndUpdate(
            { configKey: 'main_config' },
            { donationDetails: sanitizedDetails },
            { upsert: true, new: true }
        );
        req.session.success = '¡Configuración guardada con éxito!';
        res.redirect('/admin/settings');
    } catch (err) {
        req.session.error = 'Error al guardar la configuración.';
        res.redirect('/admin/settings');
    }
});




// =============================================
// RUTAS DE GESTIÓN DE BANCOS (ADMIN)
// =============================================
app.get('/admin/banks', requireAdmin, async (req, res, next) => {
    try {
        // La configuración ya está en res.locals.siteConfig
        res.render('admin/banks.html', {
            path: req.path,
            success: req.session.success,
            error: req.session.error
        });
        delete req.session.success;
        delete req.session.error;
    } catch (err) {
        next(err);
    }
});

app.post('/admin/banks/add', requireAdmin, async (req, res, next) => {
    try {
        const { bankName, accountHolderName, accountNumber, ci, details } = req.body;
        const config = await SiteConfig.findOne({ configKey: 'main_config' });
        config.bankAccounts.push({ bankName, accountHolderName, accountNumber, ci, details });
        await config.save();
        req.session.success = '¡Cuenta bancaria añadida con éxito!';
        res.redirect('/admin/banks');
    } catch (err) {
        req.session.error = 'Error al añadir la cuenta.';
        res.redirect('/admin/banks');
    }
});

app.post('/admin/banks/:id/delete', requireAdmin, async (req, res, next) => {
    try {
        const bankId = req.params.id;
        const config = await SiteConfig.findOne({ configKey: 'main_config' });
        config.bankAccounts.id(bankId).remove();
        // Si la cuenta eliminada era la activa, desactívala.
        if (config.activeBankAccountId && config.activeBankAccountId.toString() === bankId) {
            config.activeBankAccountId = null;
        }
        await config.save();
        req.session.success = 'Cuenta bancaria eliminada.';
        res.redirect('/admin/banks');
    } catch (err) {
        req.session.error = 'Error al eliminar la cuenta.';
        res.redirect('/admin/banks');
    }
});

app.post('/admin/banks/:id/set-active', requireAdmin, async (req, res, next) => {
    try {
        const bankId = req.params.id;
        await SiteConfig.findOneAndUpdate(
            { configKey: 'main_config' },
            { activeBankAccountId: bankId }
        );
        req.session.success = '¡Nueva cuenta bancaria activada para recibir donaciones!';
        res.redirect('/admin/banks');
    } catch (err) {
        req.session.error = 'Error al activar la cuenta.';
        res.redirect('/admin/banks');
    }
});




// =============================================
// RUTA DE CAMPAÑAS PENDIENTES (ADMIN)
// =============================================
app.get('/admin/pending-campaigns', requireAdmin, async (req, res, next) => {
    try {
        // Busca la primera campaña pendiente que encuentre
        const pendingCampaign = await Campaign.findOne({ status: 'pending' })
            .populate('userId', 'username email profilePic');
        
        res.render('admin/pending-campaigns.html', {
            path: req.path,
            campaign: pendingCampaign // Será null si no hay ninguna
        });
    } catch (err) {
        next(err);
    }
});




// --- VISTA DE ADMIN PARA PATROCINADORES ---
app.get('/admin/sponsors', requireAdmin, async (req, res, next) => {
    try {
        const pendingSponsors = await Sponsor.find({ status: 'pending' }).sort({ createdAt: -1 });
        const activeSponsors = await Sponsor.find({ status: 'active' }).sort({ expiresAt: 1 });
        
        // Renderiza la vista de admin que creamos antes, pasando los datos
        res.render('admin/sponsors.html', { 
            path: req.path,
            pendingSponsors,
            activeSponsors
        });
    } catch (err) {
        next(err);
    }
});

// Aprueba un patrocinador
app.post('/admin/sponsors/:id/approve', requireAdmin, async (req, res, next) => {
    try {
        const sponsor = await Sponsor.findById(req.params.id);
        if (sponsor) {
            const now = new Date();
            sponsor.status = 'active';
            sponsor.approvedAt = now;
            sponsor.expiresAt = new Date(now.setMonth(now.getMonth() + sponsor.months));
            await sponsor.save();
        }
        res.redirect('/admin/sponsors');
    } catch (err) {
        next(err);
    }
});

// Rechaza o desactiva un patrocinador
app.post('/admin/sponsors/:id/reject', requireAdmin, async (req, res, next) => {
    try {
        // Esta ruta puede servir para rechazar pendientes o desactivar activos
        const sponsor = await Sponsor.findById(req.params.id);
         if (sponsor.companyLogo) {
            const publicId = getPublicId(sponsor.companyLogo);
            if(publicId) await cloudinary.uploader.destroy(publicId);
        }
        await Sponsor.findByIdAndDelete(req.params.id);
        res.redirect('/admin/sponsors');
    } catch (err) {
        next(err);
    }
});


// =============================================
//               FIN DE LA PARTE 3
// =============================================


// =... (pegar debajo del código anterior)

// =============================================
//               SERVER.JS - PARTE 4 DE 4
//          (ADAPTADO PARA DONA PARAGUAY)
// =============================================

// =============================================
// RUTAS DE SEGURIDAD DE CUENTA
// =============================================
app.get('/settings/security', requireAuth, (req, res) => {
    // Renderiza la página de seguridad, pasando si el usuario ya tiene una contraseña o no (para usuarios de Google)
    res.render('settings/security.html', {
        error: req.session.error,
        success: req.session.success,
        hasPassword: !!req.user.password
    });
    delete req.session.error;
    delete req.session.success;
});

// Crear contraseña para usuarios de Google
app.post('/settings/create-password', requireAuth, async (req, res, next) => {
    try {
        const { newPassword, confirmPassword } = req.body;
        const user = await User.findById(req.user._id);

        if (user.password) return res.redirect('/settings/security');
        if (newPassword !== confirmPassword) throw new Error('Las contraseñas no coinciden.');
        if (newPassword.length < 6) throw new Error('La contraseña debe tener al menos 6 caracteres.');

        user.password = await bcrypt.hash(newPassword, 12);
        await user.save();
        req.session.success = 'Contraseña creada con éxito. Ahora puedes configurar tus preguntas de seguridad.';
        res.redirect('/settings/security');
    } catch (err) {
        req.session.error = err.message;
        res.redirect('/settings/security');
    }
});

// Guardar preguntas de seguridad
app.post('/settings/security', requireAuth, async (req, res, next) => {
    try {
        const { question1, answer1, question2, answer2, password } = req.body;
        const user = await User.findById(req.user._id);

        if (!user.password) throw new Error('Primero debes crear una contraseña para tu cuenta.');

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) throw new Error('La contraseña actual es incorrecta.');

        const hashedAnswer1 = await bcrypt.hash(answer1.toLowerCase().trim(), 10);
        const hashedAnswer2 = await bcrypt.hash(answer2.toLowerCase().trim(), 10);

        user.securityQuestions = [
            { question: question1, answer: hashedAnswer1 },
            { question: question2, answer: hashedAnswer2 }
        ];
        await user.save();
        req.session.success = '¡Tus preguntas de seguridad se han actualizado correctamente!';
        res.redirect('/settings/security');
    } catch (err) {
        req.session.error = err.message;
        res.redirect('/settings/security');
    }
});


// Enviar código para eliminar cuenta
app.post('/settings/send-deletion-code', requireAuth, async (req, res, next) => {
    try {
        const user = await User.findById(req.user._id);

        if (!user.verificationSecret) {
            const secret = speakeasy.generateSecret({ length: 20 });
            user.verificationSecret = secret.base32;
        }

        const code = speakeasy.totp({ secret: user.verificationSecret, encoding: 'base32', step: 300 });
        user.verificationCode = code;
        user.verificationCodeExpires = Date.now() + 300000; // 5 minutos
        await user.save();

        // --- INICIO DE LA CORRECCIÓN ---
        // Renderizamos y enviamos directamente la plantilla de eliminación.
        const emailHtml = await ejs.renderFile(path.join(__dirname, 'views', 'emails', 'delete-account-code.html'), {
            username: user.username,
            code: code
        });

        await transporter.sendMail({
            from: `"Soporte Dona Paraguay" <${process.env.EMAIL_USER}>`,
            to: user.email,
            subject: 'Acción Crítica Requerida: Eliminar tu cuenta',
            html: emailHtml
        });
        // --- FIN DE LA CORRECCIÓN ---

        res.status(200).json({ success: true, message: 'Código enviado a tu correo.' });
    } catch (err) {
        console.error("Error al enviar código de eliminación:", err);
        res.status(500).json({ success: false, message: 'Error interno del servidor.' });
    }
});

// donaparaguay/server.js

// Eliminar cuenta permanentemente
app.post('/settings/delete-account', requireAuth, async (req, res, next) => {
    const dbSession = await mongoose.startSession();
    try {
        await dbSession.withTransaction(async (session) => {
            const { password, verificationCode } = req.body;
            const userId = req.user._id;
            const user = await User.findById(userId).session(session);

            if (!user.password) throw new Error('Debes tener una contraseña para eliminar tu cuenta.');

            const isPasswordMatch = await bcrypt.compare(password, user.password);
            if (!isPasswordMatch) throw new Error('La contraseña es incorrecta.');

            if (user.verificationCode !== verificationCode || user.verificationCodeExpires < Date.now()) {
                throw new Error('El código de verificación es incorrecto o ha expirado.');
            }

            // --- INICIO DE LA CORRECCIÓN ---
            // Proceso de eliminación robusto
            const userCampaigns = await Campaign.find({ userId: userId }).session(session);
            for (const campaign of userCampaigns) {
                for (const fileUrl of campaign.files) {
                    const publicId = getPublicId(fileUrl);
                    if (publicId) {
                        // Determinamos el tipo de recurso desde la URL
                        const resourceType = fileUrl.includes('/video/') ? 'video' : 'image';
                        await cloudinary.uploader.destroy(publicId, { resource_type: resourceType });
                    }
                }
            }
            await Campaign.deleteMany({ userId: userId }).session(session);

            if (user.profilePic && !user.profilePic.includes('default')) {
                const publicId = getPublicId(user.profilePic);
                if (publicId) {
                    // Aplicamos la misma lógica para la foto de perfil
                    const resourceType = user.profilePic.includes('/video/') ? 'video' : 'image';
                    await cloudinary.uploader.destroy(publicId, { resource_type: resourceType });
                }
            }
            // --- FIN DE LA CORRECCIÓN ---

            await Verification.deleteOne({ userId: userId }).session(session);
            await Transaction.deleteMany({ $or: [{ donatorId: userId }, { organizerId: userId }] }).session(session);
            await Withdrawal.deleteMany({ userId: userId }).session(session);
            await Notification.deleteMany({ $or: [{ userId: userId }, { actorId: userId }] }).session(session);
            await User.findByIdAndDelete(userId).session(session);
        });
        req.logout((err) => {
            if (err) return next(err);
            res.redirect('/');
        });
    } catch (err) {
        req.session.error = err.message;
        res.redirect('/settings/security');
    } finally {
        await dbSession.endSession();
    }
});


// --- RUTAS PARA RECUPERACIÓN DE CONTRASEÑA ---
app.get('/forgot-password', (req, res) => res.render('forgot-password', { error: null }));
app.post('/forgot-password', loginLimiter, async (req, res, next) => {
    try {
        const user = await User.findOne({ email: req.body.email.toLowerCase() });
        if (!user) {
            return res.render('forgot-password', { success: 'Si existe una cuenta asociada a ese correo, hemos enviado las instrucciones para restablecer la contraseña.' });
        }

        const code = speakeasy.totp({ secret: user.verificationSecret, encoding: 'base32', step: 300 });
        user.verificationCode = code;
        user.verificationCodeExpires = Date.now() + 300000;
        await user.save();

        await sendCodeEmail({
            email: user.email,
            username: user.username,
            code: code,
            title: 'Recuperación de Contraseña',
            subject: `Tu código para restablecer tu contraseña es ${code}`,
            introMessage: 'Recibimos una solicitud para restablecer la contraseña de tu cuenta. Usa el siguiente código para continuar:'
        });

        req.session.resetEmail = user.email;
        res.redirect('/reset-with-code');
    } catch (err) {
        next(err);
    }
});

app.get('/reset-with-code', (req, res) => {
    if (!req.session.resetEmail) return res.redirect('/login');
    res.render('reset-with-code', { error: null, email: req.session.resetEmail });
});

app.post('/reset-with-code', async (req, res, next) => {
    try {
        const { email, code, newPassword } = req.body;
        if (email !== req.session.resetEmail) return res.redirect('/login');
        const user = await User.findOne({ email: email.toLowerCase(), verificationCode: code, verificationCodeExpires: { $gt: Date.now() } });
        if (!user) {
            return res.render('reset-with-code', { error: 'El código es incorrecto o ha expirado.', email });
        }
        user.password = await bcrypt.hash(newPassword, 12);
        user.verificationCode = undefined;
        user.verificationCodeExpires = undefined;
        await user.save();
        delete req.session.resetEmail;
        res.redirect('/login');
    } catch (err) {
        next(err);
    }
});



// =============================================
// RUTAS DE PATROCINADORES (SPONSORS)
// =============================================

// Muestra el formulario para aplicar
app.get('/sponsors/apply', async (req, res, next) => {
    try {
        const config = res.locals.siteConfig;
        const activeSponsorCount = await Sponsor.countDocuments({
            status: { $in: ['active', 'pending'] },
            expiresAt: { $gt: new Date() } 
        });

        const availableSlots = config.maxSponsorSlots - activeSponsorCount;

        res.render('sponsors-form', {
            success: null,
            error: null,
            slotsAvailable: availableSlots > 0,
            availableSlots: availableSlots > 0 ? availableSlots : 0,
            totalSlots: config.maxSponsorSlots
        });
    } catch (err) {
        next(err);
    }
});


// Procesa la solicitud del formulario
app.post('/sponsors/apply', upload.fields([
    { name: 'companyLogo', maxCount: 1 },
    { name: 'paymentProof', maxCount: 1 }
]), async (req, res, next) => {
    try {
        const config = res.locals.siteConfig;
        const activeSponsorCount = await Sponsor.countDocuments({
            status: { $in: ['active', 'pending'] }
        });

        if (activeSponsorCount >= config.maxSponsorSlots) {
            throw new Error("Lo sentimos, todos los espacios para patrocinadores ya han sido ocupados.");
        }

        const { companyName, companyWebsite, contactEmail, sponsorshipMonths } = req.body;
        if (!req.files || !req.files.companyLogo || !req.files.paymentProof) {
            throw new Error("Debes subir tanto el logo como el comprobante de pago.");
        }

        const months = parseInt(sponsorshipMonths);
        const pricePerMonth = 200000;
        let totalAmount = months * pricePerMonth;
        if (months === 12) {
            totalAmount = pricePerMonth * 10; // Descuento
        }

        const newSponsor = new Sponsor({
            companyName,
            companyWebsite,
            contactEmail,
            companyLogo: req.files.companyLogo[0].path,
            paymentProofUrl: req.files.paymentProof[0].path,
            months,
            totalAmount
        });
        await newSponsor.save();

        res.render('sponsor-success');

   } catch (err) {
    const config = res.locals.siteConfig;
    const activeSponsorCount = await Sponsor.countDocuments({
        status: { $in: ['active', 'pending'] }
    });
    
    const availableSlots = config.maxSponsorSlots - activeSponsorCount;

    res.render('sponsors-form', { 
        error: err.message, 
        success: null,
        slotsAvailable: availableSlots > 0,
        availableSlots: Math.max(0, availableSlots),
        totalSlots: config.maxSponsorSlots
    });
}
});


// =============================================
// RUTAS DE REPORTES
// =============================================
app.get('/report', requireAuth, (req, res) => {
    const { type, id } = req.query;
    res.render('report-form', {
        type, id,
        REPORT_CATEGORIES: ['Contenido inapropiado', 'Spam', 'Acoso', 'Estafa o Fraude', 'Otro']
    });
});
app.post('/report', requireAuth, async (req, res, next) => {
    try {
        const { type, id, category, reason } = req.body;
        const report = new Report({
            reportingUserId: req.user._id, type, category, reason
        });
        if (type === 'user') report.reportedUserId = id;
        else if (type === 'campaign') report.reportedCampaignId = id;
        await report.save();
        res.render('report-success');
    } catch (err) {
        next(err);
    }
});

// --- VISTA DE ADMIN PARA REPORTES ---
app.get('/admin/reports', requireAdmin, async (req, res, next) => {
    try {
        const reports = await Report.find({ status: 'pendiente' })
            .populate('reportingUserId', 'username')
            .populate('reportedUserId', 'username')
            .populate('reportedCampaignId', 'title')
            .sort({ createdAt: -1 });
        res.render('admin/reports.html', { reports, path: req.path });
    } catch (err) {
        next(err);
    }
});

app.post('/admin/report/:id/update', requireAdmin, async (req, res, next) => {
    try {
        await Report.findByIdAndUpdate(req.params.id, { status: 'revisado' });
        res.redirect('/admin/reports');
    } catch (err) {
        next(err);
    }
});















// =============================================
// RUTA PARA GENERAR SITEMAP DINÁMICO (ACTUALIZADA)
// =============================================
// =============================================
// RUTA SITEMAP MAESTRO (CEO EDITION)
// =============================================
app.get('/sitemap.xml', async (req, res, next) => {
    try {
        const baseUrl = process.env.BASE_URL || `http://localhost:${PORT}`;
        let xml = `<?xml version="1.0" encoding="UTF-8"?>`;
        xml += `<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">`;

        // 1. PÁGINAS ESTÁTICAS PRINCIPALES
        const staticPages = [
            { path: '/campaigns', changefreq: 'daily', priority: '1.0' },
            { path: '/', changefreq: 'daily', priority: '1.0' }, // La raíz también es importante
            { path: '/how-it-works', changefreq: 'monthly', priority: '0.8' },
            { path: '/about', changefreq: 'monthly', priority: '0.7' },
            { path: '/trust', changefreq: 'monthly', priority: '0.8' },
            { path: '/faq', changefreq: 'monthly', priority: '0.7' },
            { path: '/terms', changefreq: 'yearly', priority: '0.5' },
            { path: '/privacy', changefreq: 'yearly', priority: '0.5' },
            { path: '/login', changefreq: 'yearly', priority: '0.6' },
            { path: '/register', changefreq: 'yearly', priority: '0.6' },
            { path: '/sponsors/apply', changefreq: 'monthly', priority: '0.7' },
            { path: '/help-center', changefreq: 'weekly', priority: '0.8' }
        ];

        staticPages.forEach(page => {
            xml += `
                <url>
                    <loc>${baseUrl}${page.path}</loc>
                    <changefreq>${page.changefreq}</changefreq>
                    <priority>${page.priority}</priority>
                </url>`;
        });

        // 2. ARTÍCULOS DEL CENTRO DE AYUDA (Escaneo Dinámico)
        const helpArticlesDir = path.join(__dirname, 'views', 'help-articles');
        if (fs.existsSync(helpArticlesDir)) {
            const articleFiles = fs.readdirSync(helpArticlesDir);
            articleFiles.forEach(file => {
                if (file.endsWith('.html')) {
                    const slug = file.replace('.html', '');
                    xml += `
                        <url>
                            <loc>${baseUrl}/help/article/${slug}</loc>
                            <changefreq>monthly</changefreq>
                            <priority>0.7</priority>
                        </url>`;
                }
            });
        }

        // 3. TODAS LAS CAMPAÑAS APROBADAS
        const campaigns = await Campaign.find({ status: 'approved' }).select('_id updatedAt');
        campaigns.forEach(campaign => {
            xml += `
                <url>
                    <loc>${baseUrl}/campaign/${campaign._id}</loc>
                    <lastmod>${new Date(campaign.updatedAt).toISOString()}</lastmod>
                    <changefreq>daily</changefreq>
                    <priority>0.9</priority>
                </url>`;
        });

        // 4. PERFILES DE USUARIOS (SEO Masivo)
        // Excluimos baneados para no indexar contenido malo.
        // Excluimos roles Admin para seguridad (aunque el perfil sea público, es mejor priorizar usuarios reales).
        const users = await User.find({ isBanned: false, role: 'User' }).select('username updatedAt');
        users.forEach(user => {
            // Nos aseguramos de que el usuario tenga un username válido
            if (user.username) {
                const safeUsername = encodeURIComponent(user.username);
                xml += `
                    <url>
                        <loc>${baseUrl}/user/${safeUsername}</loc>
                        <lastmod>${new Date(user.updatedAt).toISOString()}</lastmod>
                        <changefreq>weekly</changefreq>
                        <priority>0.8</priority>
                    </url>`;
            }
        });

        xml += `</urlset>`;

        res.header('Content-Type', 'application/xml');
        res.send(xml);

    } catch (err) {
        console.error("Error generando sitemap:", err);
        next(err);
    }
});
// =============================================
// MANEJADORES DE ERRORES Y ARRANQUE DEL SERVIDOR
// =============================================
app.use((req, res, next) => {
    res.status(404).render('error', { message: 'Página no encontrada (404)', layout: false });
});

app.use((err, req, res, next) => {
  console.error("❌ ERROR CAPTURADO:", err.stack);
  const status = err.status || 500;
  const message = err.message || 'Ocurrió un error inesperado en el servidor.';
  res.status(status).render('error', { message, layout: false });
});

app.listen(PORT, () => console.log(`🚀 Servidor Dona Paraguay corriendo en http://localhost:${PORT}`));


// =============================================
//               FIN DEL ARCHIVO
// =============================================

