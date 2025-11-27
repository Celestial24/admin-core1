# Database Setup Instructions for iMARKET Admin Portal

## Overview
This guide will help you set up the database for the iMARKET Admin Portal with all necessary tables and sample data.

## Prerequisites
- MySQL/MariaDB server running (XAMPP includes MySQL)
- Access to phpMyAdmin or MySQL command line

## Quick Setup (Recommended)

### Easiest Method: Use the Combined Setup File
1. Open phpMyAdmin (usually at `http://localhost/phpmyadmin`)
2. Click on the "SQL" tab
3. Copy and paste the **entire contents** of `setup_database.sql`
4. Click "Go" to execute

This single file will:
- Create the database
- Create all tables
- Insert all sample data
- Set up everything automatically

Alternatively, via command line:
```bash
mysql -u root -p < setup_database.sql
```

## Manual Setup (Alternative Method)

### Step 1: Create the Database (if not exists)
```sql
CREATE DATABASE IF NOT EXISTS `core1` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE `core1`;
```

### Step 2: Run the Schema File
1. Open phpMyAdmin (usually at `http://localhost/phpmyadmin`)
2. Select the `core1` database
3. Click on the "SQL" tab
4. Copy and paste the entire contents of `database_schema.sql`
5. Click "Go" to execute

Alternatively, via command line:
```bash
mysql -u root -p core1 < database_schema.sql
```

### Step 3: Insert Sample Data
1. In phpMyAdmin, with the `core1` database selected
2. Click on the "SQL" tab
3. Copy and paste the entire contents of `sample_data.sql`
4. Click "Go" to execute

Alternatively, via command line:
```bash
mysql -u root -p core1 < sample_data.sql
```

## Database Tables Created

1. **admin_users** - Admin accounts with OTP support
2. **categories** - Product categories
3. **products** - Product inventory
4. **customers** - Customer information
5. **customer_addresses** - Shipping addresses
6. **orders** - Order management
7. **order_items** - Order line items
8. **transactions** - Payment transactions
9. **support_tickets** - Customer support tickets
10. **shipments** - Shipment tracking

## Sample Data Included

- **5 Categories**: Electronics, Food & Beverage, Office Supplies, Clothing & Apparel, Home & Living
- **10 Products**: Various products across categories
- **8 Customers**: Sample customer accounts
- **8 Addresses**: Customer shipping addresses
- **6 Orders**: Sample orders with different statuses
- **11 Order Items**: Products in orders
- **6 Transactions**: Payment records
- **4 Support Tickets**: Sample support requests
- **3 Shipments**: Tracking information

## Verification

After setup, verify the tables were created:
```sql
SHOW TABLES;
```

Check if sample data exists:
```sql
SELECT COUNT(*) FROM products;
SELECT COUNT(*) FROM orders;
SELECT COUNT(*) FROM customers;
```

## Troubleshooting

### Foreign Key Errors
If you get foreign key constraint errors, make sure to:
1. Drop existing tables in reverse dependency order
2. Run the schema file again

### Duplicate Entry Errors
If sample data insertion fails due to duplicates, the data may already exist. You can either:
1. Delete existing data: `TRUNCATE TABLE table_name;`
2. Skip the sample data insertion step

## Connection Settings

Make sure your `connection.php` or database settings in `index.php` match your MySQL configuration:
- Host: `localhost:3307` (or `localhost:3306`)
- Database: `core1`
- Username: `root` (or your MySQL username)
- Password: (your MySQL password)

## Next Steps

After database setup:
1. Log in to the admin portal
2. Dashboard will show real-time data from the database
3. Products, Orders, and Customers modules will display database records
4. You can now manage data through the admin interface

## Default Admin Account

After setup, you can log in with:
- **Username:** `admin`
- **Password:** `password`

**⚠️ IMPORTANT:** Change the default password immediately after first login!

## Notes

- The schema uses foreign key constraints for data integrity
- All tables include `created_at` and `updated_at` timestamps
- The admin_users table supports OTP authentication
- Order status can be updated through the Orders module
- Low stock alerts are automatically calculated based on product stock levels
- All data has been verified for consistency (order totals match order items, etc.)

## What's New in Version 2.0

- Fixed foreign key constraint issues
- Corrected order totals to match order items
- Improved table structure with proper indexes
- Added combined setup file for easier installation
- Enhanced data consistency and integrity
- All sample data verified and tested

