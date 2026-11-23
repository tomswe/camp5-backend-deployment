const express = require('express');
const cors = require('cors');
const { z } = require('zod');
const pool = require('./db');
const { router: authRouter, requireAuth, requireRole, csrfGuard } = require('./auth');
const cookieParser = require('cookie-parser');

const app = express();

app.set('trust proxy', 1); // wajib bila di belakang proxy/hosting agar cookie Secure bekerja

const allowedOrigins = (process.env.CLIENT_ORIGIN || 'http://localhost:5173').split(',').map((o) => o.trim().replace(/\/$/, '')).filter(Boolean)

const corsOptions = {
    origin: (origin, callback) => {
        if (!origin || allowedOrigins.includes(origin)) {
            return callback(null, true)
        }

        console.log(origin)
        return callback(new Error(`Origin ${origin} not allowed by CORS`))
    },
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'X-Token-Mode'],
    credentials: true,
}

app.use(cors(corsOptions))
// app.options('*', cors(corsOptions))
app.use(express.json());
app.use(cookieParser());
app.use(csrfGuard);
app.use('/api/auth', authRouter);

const productSchema = z.object({
    product_name: z.string({ message: "Product name is required." })
        .trim().min(3, { message: "Product name must be at least 3 characters long." }),
    product_slug: z.string({ message: "Slug is required." })
        .trim().min(3, { message: "Slug must be at least 3 characters long." })
        .regex(/^[a-z0-9]+(?:-[a-z0-9]+)*$/, { message: "Slug may only contain lowercase letters, numbers and hyphens." }),
    stock: z.number({ message: "Stock must be a number." })
        .int({ message: "Stock must be a whole number." })
        .nonnegative({ message: "Stock cannot be negative." }),
    price: z.number({ message: "Price must be a number." })
        .positive({ message: "Price must be greater than zero." })
});

const toNumber = (v) => (v === '' || v === null || v === undefined ? NaN : Number(v));

// Middleware
const validate = (schema) => (req, res, next) => {
    const body = { ...req.body, stock: toNumber(req.body?.stock), price: toNumber(req.body?.price) };

    const result = schema.safeParse(body);
    if (!result.success) {
        const errors = {};
        for (const issue of result.error.issues) {       // .issues works in Zod v3 and v4
            const field = issue.path.join('.') || '_form';
            (errors[field] ||= []).push(issue.message);
        }
        return res.status(400).json({ success: false, errors });
    }
    req.body = result.data;
    next();
};

const validId = (req, res, next) => {
    if (!/^\d+$/.test(req.params.id)) {
        return res.status(400).json({ success: false, message: "Invalid product id" });
    }
    next();
};

const handleDbError = (err, res) => {
    if (err.code === '23505') { // unique violation
        return res.status(409).json({
            success: false,
            errors: { product_slug: ["This slug is already in use."] }
        });
    }
    console.error(err);
    res.status(500).json({ success: false, message: "Internal server error" });
};

// Routes
app.get('/api/products', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM products WHERE deleted_at IS NULL ORDER BY id DESC');
        res.json({ success: true, data: result.rows });
    } catch (err) { handleDbError(err, res); }
});

app.get('/api/products/:slug', async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT * FROM products WHERE product_slug = $1 AND deleted_at IS NULL',
            [req.params.slug]
        );
        if (result.rows.length === 0) {
            return res.status(404).json({ success: false, message: "Product not found" });
        }
        res.json({ success: true, data: result.rows[0] });
    } catch (err) { handleDbError(err, res); }
});

app.post('/api/products', validate(productSchema), async (req, res) => {
    try {
        const { product_name, product_slug, stock, price } = req.body;
        const result = await pool.query(
            `INSERT INTO products (product_name, product_slug, stock, price, created_at, updated_at)
       VALUES ($1, $2, $3, $4, NOW(), NOW()) RETURNING *`,
            [product_name, product_slug, stock, price]
        );
        res.status(201).json({ success: true, data: result.rows[0] });
    } catch (err) { handleDbError(err, res); }
});

app.put('/api/products/:id', validId, validate(productSchema), async (req, res) => {
    try {
        const { product_name, product_slug, stock, price } = req.body;
        const result = await pool.query(
            `UPDATE products SET product_name = $1, product_slug = $2, stock = $3, price = $4, updated_at = NOW()
       WHERE id = $5 AND deleted_at IS NULL RETURNING *`,
            [product_name, product_slug, stock, price, req.params.id]
        );
        if (result.rows.length === 0) {
            return res.status(404).json({ success: false, message: "Product not found" });
        }
        res.json({ success: true, data: result.rows[0] });
    } catch (err) { handleDbError(err, res); }
});

app.delete('/api/products/:id', validId, async (req, res) => {
    try {
        const result = await pool.query(
            `UPDATE products SET deleted_at = NOW(), updated_at = NOW()
       WHERE id = $1 AND deleted_at IS NULL RETURNING id`,
            [req.params.id]
        );
        if (result.rows.length === 0) {
            return res.status(404).json({ success: false, message: "Product not found or already deleted" });
        }
        res.json({ success: true, message: "Product soft-deleted successfully" });
    } catch (err) { handleDbError(err, res); }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
