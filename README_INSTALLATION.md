# iMARKET Admin Portal - Installation Guide

## Quick Installation Steps

### Method 1: Automatic Installation (Recommended)

1. **Start your XAMPP server** (Apache and MySQL must be running)

2. **Open your browser** and go to:
   ```
   http://localhost/core1admin/install_database.php
   ```

3. **Click the "Install Database & Sample Data" button**

4. **Wait for the installation to complete**

5. **Login to the admin portal**:
   - Go to: `http://localhost/core1admin/index.php`
   - Username: `admin`
   - Password: `password`

### Method 2: Manual Installation via phpMyAdmin

1. **Open phpMyAdmin**: `http://localhost/phpmyadmin`

2. **Create database** (if not exists):
   - Click "New" in the left sidebar
   - Database name: `core1`
   - Collation: `utf8mb4_unicode_ci`
   - Click "Create"

3. **Import SQL files**:
   - Select the `core1` database
   - Go to "SQL" tab
   - Open `setup_database.sql` file
   - Copy and paste ALL contents into the SQL text area
   - Click "Go" to execute

   **OR** run separately:
   - First run `database_schema.sql` (creates tables)
   - Then run `sample_data.sql` (inserts sample data)

### Method 3: Command Line Installation

```bash
# Navigate to your project directory
cd C:\xampp\htdocs\core1admin

# Run the setup file
mysql -u root -p < setup_database.sql
```

When prompted, enter your MySQL password (usually empty for XAMPP default).

## Verification

After installation, verify that:

1. ✅ Database `core1` exists
2. ✅ All 10 tables are created:
   - admin_users
   - categories
   - products
   - customers
   - customer_addresses
   - orders
   - order_items
   - transactions
   - support_tickets
   - shipments
3. ✅ Sample data is inserted (check record counts)

## Default Admin Account

- **Username:** `admin`
- **Password:** `password`
- **Email:** `admin@imarket.com`

⚠️ **IMPORTANT:** Change the default password immediately after first login!

## Troubleshooting

### Problem: "Database Connection Error"

**Solution:**
1. Check if MySQL is running in XAMPP Control Panel
2. Verify database credentials in `connection.php`:
   - Host: `localhost`
   - Port: `3307` (or `3306` if different)
   - Username: `root`
   - Password: (usually empty for XAMPP)
   - Database: `core1`

### Problem: "No data showing in dashboard"

**Solution:**
1. Run `install_database.php` to verify data exists
2. Check if tables have records using phpMyAdmin
3. Verify connection settings in `connection.php`

### Problem: "Table doesn't exist" error

**Solution:**
1. Run `database_schema.sql` first to create tables
2. Then run `sample_data.sql` to insert data
3. Or use `setup_database.sql` which does both

### Problem: "Foreign key constraint fails"

**Solution:**
1. Drop all existing tables first
2. Run `setup_database.sql` which handles foreign keys properly
3. The script automatically disables foreign key checks during installation

## Database Structure

The system includes:
- **10 Tables** with proper relationships
- **Foreign key constraints** for data integrity
- **Indexes** for better performance
- **Sample data** for testing

## Next Steps

After successful installation:
1. ✅ Login with default admin account
2. ✅ Change admin password
3. ✅ Review sample products, orders, and customers
4. ✅ Customize the system for your needs

## Support

If you encounter any issues:
1. Check the error messages in `install_database.php`
2. Review MySQL error logs
3. Verify XAMPP MySQL is running
4. Check file permissions for SQL files

---

**Version:** 2.0  
**Last Updated:** 2025















