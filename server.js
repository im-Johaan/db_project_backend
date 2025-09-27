const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const env = require('dotenv');
env.config();
const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

// Middleware
app.use(cors());
app.use(express.json());


// Database connection configuration
const dbConfig = {
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false
    }
};

let db;

async function initDatabase() {
    try {
        db = new Pool(dbConfig);
        
        // Test the connection
        const client = await db.connect();
        console.log('Connected to Neon PostgreSQL database');
        client.release();
    } catch (error) {
        console.error('Database connection failed:', error);
        process.exit(1);
    }
}

// Auth middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Invalid token' });
        req.user = user;
        next();
    });
};

// Role-based access control
const requireRole = (roles) => {
    return (req, res, next) => {
        if (!roles.includes(req.user.role)) {
            return res.status(403).json({ error: 'Insufficient permissions' });
        }
        next();
    };
};

// ========================
// AUTHENTICATION ROUTES
// ========================

// Register user
app.post('/api/auth/register', async (req, res) => {
    try {
        const { name, email, password, role = 'User' } = req.body;
        
        if (!name || !email || !password) {
            return res.status(400).json({ error: 'Name, email, and password are required' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        
        const result = await db.query(
            'INSERT INTO Users (name, email, password, role) VALUES ($1, $2, $3, $4) RETURNING user_id',
            [name, email, hashedPassword, role]
        );

        res.status(201).json({ 
            message: 'User created successfully',
            user_id: result.rows[0].user_id 
        });
    } catch (error) {
        if (error.code === '23505') { // PostgreSQL unique violation
            return res.status(400).json({ error: 'Email already exists' });
        }
        res.status(500).json({ error: error.message });
    }
});

// Login user
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        const result = await db.query(
            'SELECT * FROM Users WHERE email = $1',
            [email]
        );

        if (result.rows.length === 0) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const user = result.rows[0];
        const validPassword = await bcrypt.compare(password, user.password);

        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const token = jwt.sign(
            { user_id: user.user_id, email: user.email, role: user.role },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.json({
            token,
            user: {
                user_id: user.user_id,
                name: user.name,
                email: user.email,
                role: user.role
            }
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ========================
// USER ROUTES
// ========================

// Get all users (Admin only)
app.get('/api/users', authenticateToken, requireRole(['Admin']), async (req, res) => {
    try {
        const result = await db.query(
            'SELECT user_id, name, email, role FROM Users'
        );
        res.json(result.rows);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get user by ID
app.get('/api/users/:id', authenticateToken, async (req, res) => {
    try {
        const result = await db.query(
            'SELECT user_id, name, email, role FROM Users WHERE user_id = $1',
            [req.params.id]
        );
        
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        res.json(result.rows[0]);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Update user
app.put('/api/users/:id', authenticateToken, async (req, res) => {
    try {
        const { name, email, role } = req.body;
        const userId = req.params.id;
        
        // Users can only update their own info unless they're admin
        if (req.user.user_id != userId && req.user.role !== 'Admin') {
            return res.status(403).json({ error: 'Insufficient permissions' });
        }

        const result = await db.query(
            'UPDATE Users SET name = $1, email = $2, role = $3 WHERE user_id = $4',
            [name, email, role, userId]
        );

        if (result.rowCount === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.json({ message: 'User updated successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ========================
// CATEGORY ROUTES
// ========================

// Get all categories
app.get('/api/categories', authenticateToken, async (req, res) => {
    try {
        const result = await db.query('SELECT * FROM Category');
        res.json(result.rows);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Create category
app.post('/api/categories', authenticateToken, requireRole(['Admin', 'Manager']), async (req, res) => {
    try {
        const { c_name, description } = req.body;
        
        const result = await db.query(
            'INSERT INTO Category (c_name, description) VALUES ($1, $2) RETURNING c_id',
            [c_name, description]
        );

        res.status(201).json({ 
            message: 'Category created successfully',
            c_id: result.rows[0].c_id 
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Update category
app.put('/api/categories/:id', authenticateToken, requireRole(['Admin', 'Manager']), async (req, res) => {
    try {
        const { c_name, description } = req.body;
        
        const result = await db.query(
            'UPDATE Category SET c_name = $1, description = $2 WHERE c_id = $3',
            [c_name, description, req.params.id]
        );

        if (result.rowCount === 0) {
            return res.status(404).json({ error: 'Category not found' });
        }

        res.json({ message: 'Category updated successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Delete category
app.delete('/api/categories/:id', authenticateToken, requireRole(['Admin']), async (req, res) => {
    try {
        const result = await db.query(
            'DELETE FROM Category WHERE c_id = $1',
            [req.params.id]
        );

        if (result.rowCount === 0) {
            return res.status(404).json({ error: 'Category not found' });
        }

        res.json({ message: 'Category deleted successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ========================
// PRODUCT ROUTES
// ========================

// Get all products with category info
app.get('/api/products', authenticateToken, async (req, res) => {
    try {
        const result = await db.query(`
            SELECT p.*, c.c_name as category_name 
            FROM Products p 
            LEFT JOIN Category c ON p.c_id = c.c_id
        `);
        res.json(result.rows);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get product by ID
app.get('/api/products/:id', authenticateToken, async (req, res) => {
    try {
        const result = await db.query(`
            SELECT p.*, c.c_name as category_name 
            FROM Products p 
            LEFT JOIN Category c ON p.c_id = c.c_id 
            WHERE p.p_id = $1
        `, [req.params.id]);
        
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Product not found' });
        }
        
        res.json(result.rows[0]);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Create product
app.post('/api/products', authenticateToken, requireRole(['Admin', 'Manager']), async (req, res) => {
    try {
        const { p_name, description, price, c_id } = req.body;
        
        const result = await db.query(
            'INSERT INTO Products (p_name, description, price, c_id) VALUES ($1, $2, $3, $4) RETURNING p_id',
            [p_name, description, price, c_id]
        );

        res.status(201).json({ 
            message: 'Product created successfully',
            p_id: result.rows[0].p_id 
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Update product
app.put('/api/products/:id', authenticateToken, requireRole(['Admin', 'Manager']), async (req, res) => {
    try {
        const { p_name, description, price, c_id } = req.body;
        
        const result = await db.query(
            'UPDATE Products SET p_name = $1, description = $2, price = $3, c_id = $4 WHERE p_id = $5',
            [p_name, description, price, c_id, req.params.id]
        );

        if (result.rowCount === 0) {
            return res.status(404).json({ error: 'Product not found' });
        }

        res.json({ message: 'Product updated successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Delete product
app.delete('/api/products/:id', authenticateToken, requireRole(['Admin']), async (req, res) => {
    try {
        const result = await db.query(
            'DELETE FROM Products WHERE p_id = $1',
            [req.params.id]
        );

        if (result.rowCount === 0) {
            return res.status(404).json({ error: 'Product not found' });
        }

        res.json({ message: 'Product deleted successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ========================
// SUPPLIER ROUTES
// ========================

// Get all suppliers
app.get('/api/suppliers', authenticateToken, async (req, res) => {
    try {
        const result = await db.query('SELECT * FROM Supplier');
        res.json(result.rows);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Create supplier
app.post('/api/suppliers', authenticateToken, requireRole(['Admin', 'Manager']), async (req, res) => {
    try {
        const { s_name, email, phone_number, address } = req.body;
        
        const result = await db.query(
            'INSERT INTO Supplier (s_name, email, phone_number, address) VALUES ($1, $2, $3, $4) RETURNING s_id',
            [s_name, email, phone_number, address]
        );

        res.status(201).json({ 
            message: 'Supplier created successfully',
            s_id: result.rows[0].s_id 
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Update supplier
app.put('/api/suppliers/:id', authenticateToken, requireRole(['Admin', 'Manager']), async (req, res) => {
    try {
        const { s_name, email, phone_number, address } = req.body;
        
        const result = await db.query(
            'UPDATE Supplier SET s_name = $1, email = $2, phone_number = $3, address = $4 WHERE s_id = $5',
            [s_name, email, phone_number, address, req.params.id]
        );

        if (result.rowCount === 0) {
            return res.status(404).json({ error: 'Supplier not found' });
        }

        res.json({ message: 'Supplier updated successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get supplier products
app.get('/api/suppliers/:id/products', authenticateToken, async (req, res) => {
    try {
        const result = await db.query(`
            SELECT p.*, s.s_name as supplier_name 
            FROM Products p 
            JOIN Supplies su ON p.p_id = su.p_id 
            JOIN Supplier s ON su.s_id = s.s_id 
            WHERE s.s_id = $1
        `, [req.params.id]);
        
        res.json(result.rows);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Add product to supplier
app.post('/api/suppliers/:supplierId/products/:productId', authenticateToken, requireRole(['Admin', 'Manager']), async (req, res) => {
    try {
        await db.query(
            'INSERT INTO Supplies (s_id, p_id) VALUES ($1, $2)',
            [req.params.supplierId, req.params.productId]
        );

        res.status(201).json({ message: 'Product added to supplier successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ========================
// WAREHOUSE ROUTES
// ========================

// Get all warehouses
app.get('/api/warehouses', authenticateToken, async (req, res) => {
    try {
        const result = await db.query('SELECT * FROM Warehouse');
        res.json(result.rows);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Create warehouse
app.post('/api/warehouses', authenticateToken, requireRole(['Admin', 'Manager']), async (req, res) => {
    try {
        const { w_name, capacity, location } = req.body;
        
        const result = await db.query(
            'INSERT INTO Warehouse (w_name, capacity, location) VALUES ($1, $2, $3) RETURNING w_id',
            [w_name, capacity, location]
        );

        res.status(201).json({ 
            message: 'Warehouse created successfully',
            w_id: result.rows[0].w_id 
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get warehouse products
app.get('/api/warehouses/:id/products', authenticateToken, async (req, res) => {
    try {
        const result = await db.query(`
            SELECT p.*, w.w_name as warehouse_name 
            FROM Products p 
            JOIN Stored_In si ON p.p_id = si.p_id 
            JOIN Warehouse w ON si.w_id = w.w_id 
            WHERE w.w_id = $1
        `, [req.params.id]);
        
        res.json(result.rows);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Add product to warehouse
app.post('/api/warehouses/:warehouseId/products/:productId', authenticateToken, requireRole(['Admin', 'Manager']), async (req, res) => {
    try {
        await db.query(
            'INSERT INTO Stored_In (p_id, w_id) VALUES ($1, $2)',
            [req.params.productId, req.params.warehouseId]
        );

        res.status(201).json({ message: 'Product added to warehouse successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ========================
// ORDER ROUTES
// ========================

// Get all orders
app.get('/api/orders', authenticateToken, async (req, res) => {
    try {
        let query = `
            SELECT o.*, u.name as user_name 
            FROM Orders o 
            JOIN Users u ON o.user_id = u.user_id
        `;
        let params = [];

        // Non-admin users can only see their own orders
        if (req.user.role !== 'Admin') {
            query += ' WHERE o.user_id = $1';
            params.push(req.user.user_id);
        }

        const result = await db.query(query, params);
        res.json(result.rows);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get order by ID with details
app.get('/api/orders/:id', authenticateToken, async (req, res) => {
    try {
        // Get order info
        const orderResult = await db.query(`
            SELECT o.*, u.name as user_name 
            FROM Orders o 
            JOIN Users u ON o.user_id = u.user_id 
            WHERE o.order_id = $1
        `, [req.params.id]);

        if (orderResult.rows.length === 0) {
            return res.status(404).json({ error: 'Order not found' });
        }

        const order = orderResult.rows[0];

        // Check permission
        if (req.user.role !== 'Admin' && order.user_id !== req.user.user_id) {
            return res.status(403).json({ error: 'Insufficient permissions' });
        }

        // Get order details
        const detailsResult = await db.query(`
            SELECT od.*, p.p_name 
            FROM Order_Details od 
            JOIN Products p ON od.p_id = p.p_id 
            WHERE od.order_id = $1
        `, [req.params.id]);

        order.details = detailsResult.rows;
        res.json(order);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Create order
app.post('/api/orders', authenticateToken, async (req, res) => {
    const client = await db.connect();
    try {
        await client.query('BEGIN');

        const { products } = req.body; // Array of {p_id, quantity, unit_price}
        
        // Calculate total amount
        const amount = products.reduce((total, item) => total + (item.quantity * item.unit_price), 0);

        // Create order
        const orderResult = await client.query(
            'INSERT INTO Orders (user_id, order_date, amount) VALUES ($1, CURRENT_DATE, $2) RETURNING order_id',
            [req.user.user_id, amount]
        );

        const orderId = orderResult.rows[0].order_id;

        // Add order details
        for (const product of products) {
            await client.query(
                'INSERT INTO Order_Details (order_id, p_id, quantity, unit_price) VALUES ($1, $2, $3, $4)',
                [orderId, product.p_id, product.quantity, product.unit_price]
            );

            // Create stock transaction
            const transResult = await client.query(
                'INSERT INTO Stock_Transaction (trans_type, trans_date, quantity_change) VALUES ($1, CURRENT_DATE, $2) RETURNING trans_id',
                ['OUT', -product.quantity]
            );

            // Log the transaction
            await client.query(
                'INSERT INTO Logs (order_id, p_id, trans_id) VALUES ($1, $2, $3)',
                [orderId, product.p_id, transResult.rows[0].trans_id]
            );
        }

        await client.query('COMMIT');
        res.status(201).json({ 
            message: 'Order created successfully',
            order_id: orderId 
        });
    } catch (error) {
        await client.query('ROLLBACK');
        res.status(500).json({ error: error.message });
    } finally {
        client.release();
    }
});

// Update order status (Admin/Manager only)
app.put('/api/orders/:id', authenticateToken, requireRole(['Admin', 'Manager']), async (req, res) => {
    try {
        const { amount } = req.body;
        
        const result = await db.query(
            'UPDATE Orders SET amount = $1 WHERE order_id = $2',
            [amount, req.params.id]
        );

        if (result.rowCount === 0) {
            return res.status(404).json({ error: 'Order not found' });
        }

        res.json({ message: 'Order updated successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ========================
// STOCK TRANSACTION ROUTES
// ========================

// Get all stock transactions
app.get('/api/stock-transactions', authenticateToken, requireRole(['Admin', 'Manager']), async (req, res) => {
    try {
        const result = await db.query('SELECT * FROM Stock_Transaction ORDER BY trans_date DESC');
        res.json(result.rows);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Create stock adjustment
app.post('/api/stock-transactions', authenticateToken, requireRole(['Admin', 'Manager']), async (req, res) => {
    try {
        const { trans_type, quantity_change } = req.body;
        
        const result = await db.query(
            'INSERT INTO Stock_Transaction (trans_type, trans_date, quantity_change) VALUES ($1, CURRENT_DATE, $2) RETURNING trans_id',
            [trans_type, quantity_change]
        );

        res.status(201).json({ 
            message: 'Stock transaction created successfully',
            trans_id: result.rows[0].trans_id 
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ========================
// ANALYTICS ROUTES
// ========================

// Get order summary
app.get('/api/analytics/orders', authenticateToken, requireRole(['Admin', 'Manager']), async (req, res) => {
    try {
        const result = await db.query(`
            SELECT 
                COUNT(*) as total_orders,
                SUM(amount) as total_revenue,
                AVG(amount) as avg_order_value,
                DATE(order_date) as order_date,
                COUNT(*) as daily_orders
            FROM Orders 
            GROUP BY DATE(order_date) 
            ORDER BY order_date DESC 
            LIMIT 30
        `);
        
        res.json(result.rows);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get top products
app.get('/api/analytics/products', authenticateToken, requireRole(['Admin', 'Manager']), async (req, res) => {
    try {
        const result = await db.query(`
            SELECT 
                p.p_name,
                p.price,
                SUM(od.quantity) as total_sold,
                SUM(od.quantity * od.unit_price) as total_revenue
            FROM Products p
            JOIN Order_Details od ON p.p_id = od.p_id
            GROUP BY p.p_id, p.p_name, p.price
            ORDER BY total_sold DESC
            LIMIT 10
        `);
        
        res.json(result.rows);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ========================
// HEALTH CHECK
// ========================

app.get('/api/health', (req, res) => {
    res.json({ 
        status: 'OK', 
        timestamp: new Date().toISOString(),
        service: 'Inventory Management API'
    });
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ error: 'Something went wrong!' });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Route not found' });
});


// Start server
async function startServer() {
    await initDatabase();
    app.listen(PORT, () => {
        console.log(`Server running on port ${PORT}`);
        console.log(`Health check: http://localhost:${PORT}/api/health`);
    });
}

startServer().catch(console.error);