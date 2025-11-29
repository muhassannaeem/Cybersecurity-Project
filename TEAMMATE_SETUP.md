# Quick Setup Guide for Teammates

## 🚀 Getting Started (5 Minutes)

### Step 1: Install MySQL (If not already installed)
- **Windows**: Download from https://dev.mysql.com/downloads/installer/
- **Mac**: `brew install mysql`
- **Linux**: `sudo apt-get install mysql-server`

### Step 2: Clone the Repository
```bash
git clone <your-repo-url>
cd "Cybersecurity Project"
```

### Step 3: Set Up Database

#### Option A: Using MySQL Workbench (Recommended for Beginners)
1. Open **MySQL Workbench**
2. Connect to your local MySQL server
3. Click **File → Open SQL Script**
4. Select `database/init.sql` from the project
5. Click **Execute** (⚡ icon)
6. Done! ✅

#### Option B: Using Command Line
```bash
# Login to MySQL
mysql -u root -p

# Run the initialization script
source database/init.sql

# Or in one command:
mysql -u root -p < database/init.sql
```

### Step 4: Configure Environment Variables

```bash
# In the backend folder
cd backend
cp .env.example .env
```

Edit `.env` file with your MySQL credentials:
```env
DB_HOST=localhost
DB_USER=root
DB_PASSWORD=your_mysql_password
DB_NAME=cybersecurity_db
JWT_SECRET=any-random-secret-key-here
```

### Step 5: Install Dependencies & Run

```bash
# Install backend dependencies
cd backend
npm install

# Start backend server
npm run dev

# In a new terminal, start frontend
cd frontend
npm install
npm run dev
```

---

## 🔑 Default Test Credentials

After setup, you can create a test account via signup, or use:
- **Email**: test@mail.com
- **Password**: test123

---

## 🐳 Alternative: Docker Setup (Easiest!)

If you have Docker installed:

```bash
# Start MySQL container
docker-compose up -d

# Database is automatically created and ready!
```

---

## ❓ Troubleshooting

### "Access denied for user 'root'"
**Solution**: Update `DB_PASSWORD` in `.env` with your MySQL root password

### "Database 'cybersecurity_db' doesn't exist"
**Solution**: Run the `database/init.sql` script in MySQL Workbench

### "Cannot connect to MySQL server"
**Solution**: 
- Make sure MySQL is running
- Windows: Check Services → MySQL
- Mac/Linux: `sudo systemctl start mysql`

### "Port 3306 already in use"
**Solution**: Either stop other MySQL instance or change port in `.env`:
```env
DB_PORT=3307
```

---

## 📞 Need Help?

1. Check the full guide: `database_setup_guide.md`
2. Ask in team chat
3. Check MySQL logs for errors

---

## ✅ Verification

After setup, test the connection:

```bash
cd backend
node test-db.js
```

You should see:
```
✅ Database connection successful!
📋 Available tables: users, sessions, password_resets, auth_logs
```

---

## 🔄 When Someone Updates the Database

If a teammate adds new tables or columns:

1. **Pull latest code**: `git pull`
2. **Check for new migration files** in `database/migrations/`
3. **Run new migrations** in MySQL Workbench
4. **Restart your backend server**

---

## 📊 Database Structure Overview

```
cybersecurity_db
├── users              (User accounts)
├── sessions           (Active login sessions)
├── password_resets    (Password reset tokens)
└── auth_logs          (Security audit log)
```

---

**Setup Time**: ~5 minutes  
**Difficulty**: Easy  
**Last Updated**: 2025-11-23
