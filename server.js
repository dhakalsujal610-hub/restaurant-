require('dotenv').config();
const express = require('express');
const path = require('path');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const db = require('./db');

// multer is only used for menu uploads later in the file
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, path.join(__dirname, 'public', 'uploads'));
  },
  filename: (req, file, cb) => {
    const uniqueName = Date.now() + '-' + file.originalname.replace(/\s+/g, '_');
    cb(null, uniqueName);
  }
});
const upload = multer({ storage });

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Session configuration (BEFORE routes that use it)
app.use(session({
  secret: process.env.SESSION_SECRET || 'cafe-admin-secret-2026',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));

// Middleware to check authentication
const isAuthenticated = (req, res, next) => {
  if (req.session.admin) {
    next();
  } else {
    res.status(401).json({ success: false, message: 'Unauthorized' });
  }
};

// ==== ADMIN ROUTES (NB: defined before static middleware so they
// aren’t accidentally shadowed by a file lookup) ====
app.get('/admin/login', (req, res) => {
  if (req.session.admin) {
    // already logged in → dashboard
    return res.redirect('/admin/dashboard');
  }
  res.sendFile(path.join(__dirname, 'public', 'admin', 'login.html'));
});

app.get('/admin/dashboard', (req, res) => {
  if (!req.session.admin) {
    // protect dashboard
    return res.redirect('/admin/login');
  }
  res.sendFile(path.join(__dirname, 'public', 'admin', 'dashboard.html'));
});

// make sure admin CSS/JS/images can be found by absolute paths
// note: this middleware only delivers files under /public/admin,
// so it won’t intercept /admin/login or /admin/dashboard because
// the routes above run first.
app.use('/admin', express.static(path.join(__dirname, 'public', 'admin')));

// general static dispatcher for everything else (homepage, uploads, etc.)
app.use(express.static(path.join(__dirname, 'public')));
// serve uploaded images folder as static as well
app.use('/uploads', express.static(path.join(__dirname, 'public', 'uploads')));

// Auth Routes
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ success: false, message: 'Username and password required' });
    }

    db.get('SELECT * FROM admin_users WHERE username = ?', [username], async (err, user) => {
      if (err) {
        return res.status(500).json({ success: false, message: 'Database error' });
      }

      if (!user) {
        return res.status(401).json({ success: false, message: 'Invalid credentials' });
      }

      const validPassword = bcrypt.compareSync(password, user.password);
      if (!validPassword) {
        return res.status(401).json({ success: false, message: 'Invalid credentials' });
      }

      req.session.admin = { id: user.id, username: user.username };
      res.json({ success: true, message: 'Login successful' });
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.post('/api/auth/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ success: false, message: 'Logout failed' });
    }
    res.json({ success: true, message: 'Logged out' });
  });
});

app.get('/api/auth/check', (req, res) => {
  if (req.session.admin) {
    res.json({ authenticated: true, username: req.session.admin.username });
  } else {
    res.json({ authenticated: false });
  }
});

// Order Routes
app.post('/api/orders', async (req, res) => {
  try {
    const { customer, items, total } = req.body;

    if (!customer || !customer.name || !customer.phone || !items || !total) {
      return res.status(400).json({ success: false, message: 'Missing required fields' });
    }

    const itemsJSON = JSON.stringify(items);
    
    db.run(
      `INSERT INTO orders (customer_name, phone, email, address, items, total, status, payment_status)
       VALUES (?, ?, ?, ?, ?, ?, 'pending', 'unpaid')`,
      [customer.name, customer.phone, customer.email || '', customer.address || '', itemsJSON, total],
      function(err) {
        if (err) {
          console.error('Insert error:', err);
          return res.status(500).json({ success: false, message: 'Failed to create order' });
        }
        res.json({ success: true, orderId: this.lastID });
      }
    );
  } catch (error) {
    console.error('Order creation error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/api/orders', isAuthenticated, (req, res) => {
  try {
    db.all('SELECT * FROM orders ORDER BY created_at DESC', (err, rows) => {
      if (err) {
        return res.status(500).json({ success: false, message: 'Database error' });
      }
      
      const orders = rows.map(order => ({
        ...order,
        items: JSON.parse(order.items)
      }));
      
      res.json(orders);
    });
  } catch (error) {
    console.error('Error fetching orders:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/api/orders/:id', isAuthenticated, (req, res) => {
  try {
    const { id } = req.params;
    db.get('SELECT * FROM orders WHERE id = ?', [id], (err, order) => {
      if (err) {
        return res.status(500).json({ success: false, message: 'Database error' });
      }
      if (!order) {
        return res.status(404).json({ success: false, message: 'Order not found' });
      }
      
      order.items = JSON.parse(order.items);
      res.json(order);
    });
  } catch (error) {
    console.error('Error fetching order:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.put('/api/orders/:id/status', isAuthenticated, (req, res) => {
  try {
    const { id } = req.params;
    const { status, payment_status } = req.body;

    if (!status) {
      return res.status(400).json({ success: false, message: 'Status required' });
    }

    const validStatuses = ['pending', 'preparing', 'completed', 'cancelled'];
    if (!validStatuses.includes(status)) {
      return res.status(400).json({ success: false, message: 'Invalid status' });
    }

    db.run(
      'UPDATE orders SET status = ?, payment_status = ? WHERE id = ?',
      [status, payment_status || 'unpaid', id],
      function(err) {
        if (err) {
          return res.status(500).json({ success: false, message: 'Failed to update order' });
        }
        res.json({ success: true, message: 'Order status updated' });
      }
    );
  } catch (error) {
    console.error('Error updating order:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.delete('/api/orders/:id', isAuthenticated, (req, res) => {
  try {
    const { id } = req.params;
    db.run('DELETE FROM orders WHERE id = ?', [id], function(err) {
      if (err) {
        return res.status(500).json({ success: false, message: 'Failed to delete order' });
      }
      res.json({ success: true, message: 'Order deleted' });
    });
  } catch (error) {
    console.error('Error deleting order:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Contact Routes
app.post('/api/contact', (req, res) => {
  try {
    const { name, phone, email, subject, message } = req.body;

    if (!name || !email || !message) {
      return res.status(400).json({ success: false, message: 'Missing required fields' });
    }

    db.run(
      `INSERT INTO contacts (name, phone, email, subject, message, is_read)
       VALUES (?, ?, ?, ?, ?, 0)`,
      [name, phone || '', email, subject || '', message],
      function(err) {
        if (err) {
          console.error('Insert error:', err);
          return res.status(500).json({ success: false, message: 'Failed to save contact' });
        }
        res.json({ success: true, message: 'Thank you for contacting us!' });
      }
    );
  } catch (error) {
    console.error('Contact creation error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/api/contacts', isAuthenticated, (req, res) => {
  try {
    db.all('SELECT * FROM contacts ORDER BY created_at DESC', (err, rows) => {
      if (err) {
        return res.status(500).json({ success: false, message: 'Database error' });
      }
      res.json(rows || []);
    });
  } catch (error) {
    console.error('Error fetching contacts:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.delete('/api/contacts/:id', isAuthenticated, (req, res) => {
  try {
    const { id } = req.params;
    db.run('DELETE FROM contacts WHERE id = ?', [id], function(err) {
      if (err) {
        return res.status(500).json({ success: false, message: 'Failed to delete contact' });
      }
      res.json({ success: true, message: 'Contact deleted' });
    });
  } catch (error) {
    console.error('Error deleting contact:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.put('/api/contacts/:id/read', isAuthenticated, (req, res) => {
  try {
    const { id } = req.params;
    db.run('UPDATE contacts SET is_read = 1 WHERE id = ?', [id], function(err) {
      if (err) {
        return res.status(500).json({ success: false, message: 'Failed to update contact' });
      }
      res.json({ success: true, message: 'Contact marked as read' });
    });
  } catch (error) {
    console.error('Error updating contact:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Menu routes for admin to manage food items
app.get('/api/menu', (req, res) => { // public endpoint
  try {
    db.all('SELECT * FROM menu_items ORDER BY created_at DESC', (err, rows) => {
      if (err) return res.status(500).json({ success: false, message: 'Database error' });
      res.json(rows || []);
    });
  } catch (error) {
    console.error('Error fetching menu:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.post('/api/menu', isAuthenticated, upload.single('image'), (req, res) => {
  try {
    const { name, price } = req.body;
    if (!name || !price) {
      return res.status(400).json({ success: false, message: 'Name and price required' });
    }
    const imagePath = req.file ? '/uploads/' + req.file.filename : null;
    db.run(
      'INSERT INTO menu_items (name, price, image) VALUES (?, ?, ?)',
      [name, price, imagePath],
      function(err) {
        if (err) return res.status(500).json({ success: false, message: 'Database error' });
        res.json({ success: true, itemId: this.lastID });
      }
    );
  } catch (error) {
    console.error('Error creating menu item:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.put('/api/menu/:id', isAuthenticated, upload.single('image'), (req, res) => {
  try {
    const { id } = req.params;
    const { name, price } = req.body;
    let imagePath;
    if (req.file) {
      imagePath = '/uploads/' + req.file.filename;
    }
    const updates = [];
    const params = [];
    if (name) { updates.push('name = ?'); params.push(name); }
    if (price) { updates.push('price = ?'); params.push(price); }
    if (imagePath) { updates.push('image = ?'); params.push(imagePath); }
    if (updates.length === 0) {
      return res.status(400).json({ success: false, message: 'Nothing to update' });
    }
    params.push(id);
    db.run(
      `UPDATE menu_items SET ${updates.join(', ')} WHERE id = ?`,
      params,
      function(err) {
        if (err) return res.status(500).json({ success: false, message: 'Database error' });
        res.json({ success: true, message: 'Menu item updated' });
      }
    );
  } catch (error) {
    console.error('Error updating menu item:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.delete('/api/menu/:id', isAuthenticated, (req, res) => {
  try {
    const { id } = req.params;
    db.run('DELETE FROM menu_items WHERE id = ?', [id], function(err) {
      if (err) return res.status(500).json({ success: false, message: 'Database error' });
      res.json({ success: true, message: 'Menu item deleted' });
    });
  } catch (error) {
    console.error('Error deleting menu item:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Dashboard Stats
app.get('/api/stats', isAuthenticated, (req, res) => {
  try {
    db.all(`
      SELECT 
        (SELECT COUNT(*) FROM contacts) as total_contacts,
        (SELECT COUNT(*) FROM orders) as total_orders,
        (SELECT SUM(total) FROM orders) as total_revenue,
        (SELECT COUNT(*) FROM orders WHERE date(created_at) = date('now')) as today_orders,
        (SELECT COUNT(*) FROM orders WHERE status = 'pending') as pending_orders,
        (SELECT COUNT(*) FROM orders WHERE status = 'completed') as completed_orders
    `, (err, rows) => {
      if (err) {
        return res.status(500).json({ success: false, message: 'Database error' });
      }
      const stats = rows[0] || {};
      res.json({
        total_contacts: stats.total_contacts || 0,
        total_orders: stats.total_orders || 0,
        total_revenue: stats.total_revenue || 0,
        today_orders: stats.today_orders || 0,
        pending_orders: stats.pending_orders || 0,
        completed_orders: stats.completed_orders || 0
      });
    });
  } catch (error) {
    console.error('Error fetching stats:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Fallback SPA handler (LAST)
app.use((req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`🍔 Cafe Admin Server listening on http://localhost:${PORT}`);
  console.log(`📊 Admin Panel: http://localhost:${PORT}/admin/login`);
});