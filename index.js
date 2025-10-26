const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
require('dotenv').config();
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

const app = express();
const port = process.env.PORT || 5000;

app.use(cors({
  origin: 'http://localhost:5173',
  credentials: true
}));

app.use(express.json());

// Global variables for collections
let menuCollection, reviewCollection, cartCollection, userCollection, ordersCollection, couponsCollection;

// MongoDB connection
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASSWORD}@cluster0.skka1tn.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});

// Connect to MongoDB
async function run() {
  try {
    await client.connect();
    const db = client.db("MoodieFoodieDb");
    menuCollection = db.collection("menu");
    reviewCollection = db.collection("reviews");
    cartCollection = db.collection("carts");
    userCollection = db.collection("users");
    ordersCollection = db.collection("orders");
    couponsCollection = db.collection("coupons");

    console.log("✅ Connected to MongoDB!");

    // Clean up duplicate users
    const duplicates = await userCollection.aggregate([
      { $group: { _id: "$userId", docs: { $push: "$$ROOT" }, count: { $sum: 1 } }},
      { $match: { count: { $gt: 1 } }}
    ]).toArray();

    for (const dup of duplicates) {
      const [keep, ...remove] = dup.docs;
      const idsToDelete = remove.map(doc => doc._id);
      await userCollection.deleteMany({ _id: { $in: idsToDelete } });
    }

    await userCollection.createIndex({ userId: 1 }, { unique: true });

    if (duplicates.length > 0) {
      console.warn("⚠️ Duplicate users found:", duplicates.length);
    }

  } catch (err) {
    console.error("❌ MongoDB connection failed:", err);
  }
}

run().catch(console.dir);

// Middleware to check if DB is connected
app.use((req, res, next) => {
  if (!menuCollection || !userCollection || !cartCollection) {
    return res.status(503).json({ error: "Database not ready. Please try again." });
  }
  next();
});

// Verify JWT middleware
function verifyJWT(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).send({ error: 'No token provided' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    res.status(403).send({ error: 'Invalid or expired token' });
  }
}

// JWT related API
app.post('/jwt', async (req, res) => {
  try {
    const { userId, email } = req.body;

    if (!userId || !email) {
      return res.status(400).json({ error: 'Missing required user information' });
    }

    if (!process.env.JWT_SECRET) {
      console.error('JWT_SECRET is not set in environment');
      return res.status(500).json({ error: 'Server configuration error' });
    }

    // Look up user in DB to get their stored role
    const user = await userCollection.findOne({ userId });
    const role = user?.role || 'user';

    const payload = { userId, email, role };
    const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '2h' });

    return res.status(200).json({ token });
  } catch (err) {
    console.error('Error in /jwt route:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// Basic routes
app.get('/', (req, res) => {
  res.send('Welcome to MoodieFoodie API! Try /menu for menu items.');
});

app.get('/menu', async (req, res) => {
  try {
    const items = await menuCollection.find().toArray();
    res.send(items);
  } catch {
    res.status(500).send({ error: "Menu fetch failed." });
  }
});

app.get('/reviews', async (req, res) => {
  try {
    const reviews = await reviewCollection.find().toArray();
    res.send(reviews);
  } catch {
    res.status(500).send({ error: "Review fetch failed." });
  }
});

app.get('/users', async (req, res) => {
  try {
    const allUsers = await userCollection.find().toArray();
    res.send(allUsers);
  } catch (err) {
    res.status(500).send({ error: "Failed to fetch users" });
  }
});

app.get('/cart', async (req, res) => {
  try {
    const allCarts = await cartCollection.find().toArray();
    res.send(allCarts);
  } catch {
    res.status(500).send({ error: "Failed to fetch carts." });
  }
});

app.patch('/user/:userId', async (req, res) => {
  const { userId } = req.params;
  const profile = req.body;

  if (!userId || !profile) {
    return res.status(400).send({ error: "Missing userId or profile data." });
  }

  try {
    const result = await userCollection.findOneAndUpdate(
      { userId },
      { $set: profile },
      { upsert: true, returnDocument: 'after' }
    );
    res.send(result.value);
  } catch (err) {
    res.status(500).send({ error: "Profile update failed." });
  }
});

app.get('/user/:userId', async (req, res) => {
  const { userId } = req.params;
  try {
    const user = await userCollection.findOne({ userId });
    if (!user) return res.status(404).send({ error: "User not found" });
    res.send(user);
  } catch {
    res.status(500).send({ error: "User fetch failed" });
  }
});

app.get('/orders/:userId', async (req, res) => {
  const { userId } = req.params;
  try {
    const orders = await ordersCollection.find({ userId }).toArray();
    res.send(orders);
  } catch {
    res.status(500).send({ error: "Order fetch failed." });
  }
});

app.get('/coupons/:userId', async (req, res) => {
  const { userId } = req.params;
  try {
    const coupons = await couponsCollection.find({ userId }).toArray();
    res.send(coupons);
  } catch {
    res.status(500).send({ error: "Coupon fetch failed." });
  }
});

app.post('/coupons', async (req, res) => {
  const { userId, code, discount } = req.body;
  if (!userId || !code || !discount) return res.status(400).send({ error: "Missing coupon data." });

  try {
    const result = await couponsCollection.insertOne({ userId, code, discount });
    res.send({ message: "Coupon added.", result });
  } catch {
    res.status(500).send({ error: "Coupon creation failed." });
  }
});

app.patch('/coupons/:couponId', async (req, res) => {
  const { couponId } = req.params;
  const updates = req.body;

  try {
    const result = await couponsCollection.updateOne(
      { _id: new ObjectId(couponId) },
      { $set: updates }
    );
    res.send({ message: "Coupon updated.", result });
  } catch {
    res.status(500).send({ error: "Coupon update failed." });
  }
});

// Order creation
app.post('/orders', async (req, res) => {
  const { userId, items, total, status = "pending" } = req.body;
  
  if (!userId || !items || items.length === 0 || total == null || isNaN(total)) {
    return res.status(400).send({ error: "Missing or invalid order data." });
  }

  try {
    // Get user info first
    const user = await userCollection.findOne({ userId });
    if (!user) {
      return res.status(404).send({ error: "User not found" });
    }

    // Create the order with user name
    const result = await ordersCollection.insertOne({ 
      userId, 
      userName: user.name,
      items, 
      total, 
      status, 
      createdAt: new Date() 
    });

    // Clear the user's cart
    await cartCollection.updateOne(
      { userId }, 
      { $set: { items: [] } }
    );
    
    res.send({ message: "Order placed and cart cleared.", result });
  } catch (err) {
    console.error("Order creation failed:", err);
    res.status(500).send({ error: "Order creation failed." });
  }
});

app.patch('/orders/:orderId', async (req, res) => {
  const { orderId } = req.params;
  const { status } = req.body;
  if (!status) return res.status(400).send({ error: "Missing status." });

  try {
    const result = await ordersCollection.updateOne(
      { _id: new ObjectId(orderId) },
      { $set: { status } }
    );
    res.send({ message: "Order status updated.", result });
  } catch {
    res.status(500).send({ error: "Order update failed." });
  }
});

app.get('/cart/:userId', async (req, res) => {
  const { userId } = req.params;
  try {
    const cart = await cartCollection.findOne({ userId });
    res.send(cart || { userId, items: [] });
  } catch {
    res.status(500).send({ error: "Cart fetch failed." });
  }
});

app.post('/cart', async (req, res) => {
  const { userId, item } = req.body;
  if (!userId || !item || !item._id) return res.status(400).send({ error: "Invalid payload." });

  try {
    let cart = await cartCollection.findOne({ userId });
    if (!cart) {
      await cartCollection.insertOne({ userId, items: [{ ...item, quantity: 1 }] });
    } else {
      const existing = cart.items.find(i => String(i._id) === String(item._id));
      if (existing) {
        cart.items = cart.items.map(i =>
          i._id === item._id ? { ...i, quantity: i.quantity + 1 } : i
        );
      } else {
        cart.items.push({ ...item, quantity: 1 });
      }
      await cartCollection.updateOne({ userId }, { $set: { items: cart.items } });
    }
    const updatedCart = await cartCollection.findOne({ userId });
    res.send(updatedCart);
  } catch {
    res.status(500).send({ error: "Add to cart failed." });
  }
});

app.put('/cart/:userId/:itemId', async (req, res) => {
  const { userId, itemId } = req.params;
  const { action } = req.body;
  if (!userId || !itemId || !["increment", "decrement"].includes(action)) {
    return res.status(400).send({ error: "Invalid request." });
  }

  try {
    const cart = await cartCollection.findOne({ userId });
    if (!cart) return res.status(404).send({ error: "Cart not found." });

    cart.items = cart.items.map(item => {
      if (String(item._id) === String(itemId)) {
        item.quantity = action === 'increment' ? item.quantity + 1 : Math.max(1, item.quantity - 1);
      }
      return item;
    });

    await cartCollection.updateOne({ userId }, { $set: { items: cart.items } });
    res.send(cart);
  } catch {
    res.status(500).send({ error: "Quantity update failed." });
  }
});

// User management
app.post('/user', async (req, res) => {
  const { userId, name, email } = req.body;
  if (!userId || !email) return res.status(400).send({ error: "Missing user data." });

  try {
    // Fix old users missing "role"
    await userCollection.updateMany(
      { role: { $exists: false } },
      { $set: { role: "user" } }
    );

    // Check if user already exists
    const existingUser = await userCollection.findOne({ userId });

    if (existingUser) {
      await userCollection.updateOne(
        { userId },
        {
          $set: { name, email, lastLogin: new Date() }
        }
      );
      return res.status(200).send({ message: "User updated (existing)." });
    }

    // Create new user
    const newUser = {
      userId,
      name,
      email,
      role: 'user',
      createdAt: new Date(),
      lastLogin: new Date()
    };

    await userCollection.insertOne(newUser);
    return res.send({ message: "User created successfully." });

  } catch (err) {
    console.error("User sync failed:", err);
    res.status(500).send({ error: "User sync failed." });
  }
});

app.delete('/cart/:userId/:itemId', async (req, res) => {
  const { userId, itemId } = req.params;
  try {
    await cartCollection.updateOne({ userId }, { $pull: { items: { _id: itemId } } });
    const updatedCart = await cartCollection.findOne({ userId });
    res.send(updatedCart);
  } catch {
    res.status(500).send({ error: "Remove item failed." });
  }
});

// Admin routes
app.get('/admin/users', verifyJWT, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).send({ error: 'Access denied' });
  }

  try {
    const users = await userCollection.find().toArray();
    res.send(users);
  } catch (err) {
    console.error("Failed to fetch users:", err);
    res.status(500).send({ error: "User fetch failed." });
  }
});

app.get('/admin/orders', verifyJWT, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).send({ error: 'Access denied' });
  }

  try {
    const orders = await ordersCollection.find().toArray();
    res.send(orders);
  } catch (err) {
    console.error("Failed to fetch orders:", err);
    res.status(500).send({ error: "Order fetch failed." });
  }
});

app.post('/admin/coupons', verifyJWT, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).send({ error: 'Access denied' });
  }

  const { code, discount, expiry } = req.body;

  if (!code || isNaN(discount) || !Date.parse(expiry)) {
    return res.status(400).send({ error: "Invalid coupon data." });
  }

  const status = new Date(expiry) < new Date() ? "expired" : "active";

  try {
    const result = await couponsCollection.insertOne({ code, discount, expiry, status });
    res.send({ message: "Coupon added.", result });
  } catch {
    res.status(500).send({ error: "Coupon creation failed." });
  }
});

app.get('/admin/coupons', verifyJWT, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).send({ error: 'Access denied' });
  }
  try {
    const coupons = await couponsCollection.find().toArray();
    res.send(coupons);
  } catch (err) {
    console.error("Failed to fetch coupons:", err);
    res.status(500).send({ error: "Coupon fetch failed." });
  }
});

app.delete('/admin/coupons/:couponId', verifyJWT, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).send({ error: 'Access denied' });
  }
  const { couponId } = req.params;
  try {
    const result = await couponsCollection.deleteOne({ _id: new ObjectId(couponId) });
    res.send({ message: "Coupon deleted.", result });
  } catch {
    res.status(500).send({ error: "Coupon deletion failed." });
  }
});

app.patch('/admin/coupons/:couponId', verifyJWT, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).send({ error: 'Access denied' });
  }
  const { couponId } = req.params;
  const updates = req.body;

  try {
    const result = await couponsCollection.updateOne(
      { _id: new ObjectId(couponId) },
      { $set: updates }
    );
    res.send({ message: "Coupon updated.", result });
  } catch {
    res.status(500).send({ error: "Coupon update failed." });
  }
});

app.get('/admin/inventory', verifyJWT, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).send({ error: 'Access denied' });
  }

  try {
    const items = await menuCollection.find().toArray();
    res.send(items);
  } catch (err) {
    console.error("Failed to fetch inventory:", err);
    res.status(500).send({ error: "Inventory fetch failed." });
  }
});

app.get('/admin/analytics', verifyJWT, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).send({ error: 'Access denied' });
  }
  try {
    const totalUsers = await userCollection.countDocuments();
    const totalOrders = await ordersCollection.countDocuments();
    const totalRevenue = await ordersCollection.aggregate([
      { $group: { _id: null, total: { $sum: "$total" } } }
    ]).toArray();

    res.send({
      totalUsers,
      totalOrders,
      totalRevenue: totalRevenue[0]?.total || 0
    });
  } catch (err) {
    console.error("Failed to fetch analytics:", err);
    res.status(500).send({ error: "Analytics fetch failed." });
  }
});

// Add item
app.post('/admin/inventory', verifyJWT, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).send({ error: 'Access denied' });
  }
  const newItem = req.body;
  const result = await menuCollection.insertOne(newItem);
  res.send(result);
});

// Delete item
app.delete('/admin/inventory/:id', verifyJWT, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).send({ error: 'Access denied' });
  }
  const id = req.params.id;
  console.log("Received delete request for ID:", id);

  try {
    const result = await menuCollection.deleteOne({ _id: new ObjectId(id) });
    console.log("Delete result:", result);
    res.send(result);
  } catch (err) {
    console.error("Delete failed:", err);
    res.status(500).send({ error: "Delete failed." });
  }
});

// Update item
app.put('/admin/inventory/:id', verifyJWT, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).send({ error: 'Access denied' });
  }
  const id = req.params.id;
  const updatedItem = req.body;
  try {
    const result = await menuCollection.updateOne(
      { _id: new ObjectId(id) },
      { $set: updatedItem }
    );
    res.send(result);
  } catch (err) {
    console.error("Failed to update item:", err);
    res.status(500).send({ error: "Update failed." });
  }
});

// Stripe payment (safe for both local and production)
app.post('/create-payment-intent', async (req, res) => {
  const { amount } = req.body;

  // If STRIPE_SECRET_KEY is missing (like on Render), disable payment route
  if (!process.env.STRIPE_SECRET_KEY) {
    console.warn("⚠️ Stripe key missing — payments disabled.");
    return res.status(403).json({
      error: "Stripe is not configured in this environment."
    });
  }

  try {
    const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

    const paymentIntent = await stripe.paymentIntents.create({
      amount: Math.round(amount * 100), // convert to cents
      currency: 'usd',
      automatic_payment_methods: { enabled: true }
    });

    res.json({ clientSecret: paymentIntent.client_secret });
  } catch (err) {
    console.error("❌ Stripe payment error:", err);
    res.status(500).json({ error: "Payment initiation failed." });
  }
});

// Start server
app.listen(port, () => {
  console.log(`🚀 MoodieFoodie server running on port ${port}`);
});