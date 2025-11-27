-- =========================================================================
-- iMARKET Admin Portal - Kumpletong Database Setup Script
-- Ang file na ito ay pinagsama-samang schema at sample data.
-- I-run ang file na ito sa inyong MySQL server.
-- =========================================================================

-- =========================================================================
-- STEP 1: I-CREATE AT GAMITIN ANG DATABASE
-- =========================================================================
CREATE DATABASE IF NOT EXISTS `core1` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE `core1`;

-- I-disable ang foreign key checks para sa malinis na installation
SET FOREIGN_KEY_CHECKS = 0;

-- =========================================================================
-- STEP 2: I-DROP AT I-CREATE ANG MGA TABLES (Schema)
-- =========================================================================

-- 1. ADMIN USERS TABLE (Kasama ang OTP fields)
DROP TABLE IF EXISTS `admin_users`;
CREATE TABLE `admin_users` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `username` varchar(50) NOT NULL,
  `password_hash` varchar(255) NOT NULL,
  `role` varchar(50) DEFAULT 'Admin',
  `full_name` varchar(100) DEFAULT NULL,
  `email` varchar(100) DEFAULT NULL,
  `phone_number` varchar(20) DEFAULT NULL,
  `otp_code` varchar(6) DEFAULT NULL,
  `otp_expiry` datetime DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `username` (`username`),
  UNIQUE KEY `email` (`email`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 2. CATEGORIES TABLE
DROP TABLE IF EXISTS `categories`;
CREATE TABLE `categories` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(100) NOT NULL,
  `slug` varchar(100) NOT NULL,
  `description` text DEFAULT NULL,
  `status` enum('Active','Inactive') DEFAULT 'Active',
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `slug` (`slug`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 3. PRODUCTS TABLE
DROP TABLE IF EXISTS `products`;
CREATE TABLE `products` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(200) NOT NULL,
  `slug` varchar(200) NOT NULL,
  `description` text DEFAULT NULL,
  `price` decimal(10,2) NOT NULL,
  `stock` int(11) DEFAULT 0,
  `category_id` int(11) NOT NULL,
  `status` enum('Active','Inactive','Low Stock','Critical Stock') DEFAULT 'Active',
  `image_url` varchar(500) DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `slug` (`slug`),
  KEY `category_id` (`category_id`),
  KEY `status` (`status`),
  CONSTRAINT `products_ibfk_1` FOREIGN KEY (`category_id`) REFERENCES `categories` (`id`) ON DELETE RESTRICT ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 4. CUSTOMERS TABLE
DROP TABLE IF EXISTS `customers`;
CREATE TABLE `customers` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `full_name` varchar(100) NOT NULL,
  `email` varchar(100) NOT NULL,
  `phone_number` varchar(20) DEFAULT NULL,
  `status` enum('Active','Inactive','Banned') DEFAULT 'Active',
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `email` (`email`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 5. CUSTOMER ADDRESSES TABLE
DROP TABLE IF EXISTS `customer_addresses`;
CREATE TABLE `customer_addresses` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `customer_id` int(11) NOT NULL,
  `address_line1` varchar(200) NOT NULL,
  `address_line2` varchar(200) DEFAULT NULL,
  `city` varchar(100) NOT NULL,
  `province` varchar(100) NOT NULL,
  `postal_code` varchar(20) DEFAULT NULL,
  `country` varchar(50) DEFAULT 'Philippines',
  `status` enum('Verified','Pending Validation','Requires Review') DEFAULT 'Pending Validation',
  `is_default` tinyint(1) DEFAULT 0,
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `customer_id` (`customer_id`),
  CONSTRAINT `customer_addresses_ibfk_1` FOREIGN KEY (`customer_id`) REFERENCES `customers` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 6. ORDERS TABLE
DROP TABLE IF EXISTS `orders`;
CREATE TABLE `orders` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `order_number` varchar(50) NOT NULL,
  `customer_id` int(11) NOT NULL,
  `address_id` int(11) NOT NULL,
  `total_amount` decimal(10,2) NOT NULL,
  `status` enum('Pending','Processing','Shipped','Delivered','Cancelled') DEFAULT 'Pending',
  `payment_status` enum('Pending','Paid','Failed','Refunded') DEFAULT 'Pending',
  `order_date` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `shipped_date` datetime DEFAULT NULL,
  `delivered_date` datetime DEFAULT NULL,
  `notes` text DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `order_number` (`order_number`),
  KEY `customer_id` (`customer_id`),
  KEY `address_id` (`address_id`),
  KEY `status` (`status`),
  CONSTRAINT `orders_ibfk_1` FOREIGN KEY (`customer_id`) REFERENCES `customers` (`id`) ON DELETE RESTRICT ON UPDATE CASCADE,
  CONSTRAINT `orders_ibfk_2` FOREIGN KEY (`address_id`) REFERENCES `customer_addresses` (`id`) ON DELETE RESTRICT ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 7. ORDER ITEMS TABLE
DROP TABLE IF EXISTS `order_items`;
CREATE TABLE `order_items` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `order_id` int(11) NOT NULL,
  `product_id` int(11) NOT NULL,
  `quantity` int(11) NOT NULL,
  `price` decimal(10,2) NOT NULL,
  `subtotal` decimal(10,2) NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `order_id` (`order_id`),
  KEY `product_id` (`product_id`),
  CONSTRAINT `order_items_ibfk_1` FOREIGN KEY (`order_id`) REFERENCES `orders` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `order_items_ibfk_2` FOREIGN KEY (`product_id`) REFERENCES `products` (`id`) ON DELETE RESTRICT ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 8. TRANSACTIONS TABLE
DROP TABLE IF EXISTS `transactions`;
CREATE TABLE `transactions` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `order_id` int(11) NOT NULL,
  `transaction_number` varchar(50) NOT NULL,
  `payment_method` enum('Cash','Credit Card','Debit Card','Bank Transfer','E-Wallet') DEFAULT 'Cash',
  `amount` decimal(10,2) NOT NULL,
  `status` enum('Pending','Completed','Failed','Refunded') DEFAULT 'Pending',
  `transaction_date` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `notes` text DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `transaction_number` (`transaction_number`),
  KEY `order_id` (`order_id`),
  CONSTRAINT `transactions_ibfk_1` FOREIGN KEY (`order_id`) REFERENCES `orders` (`id`) ON DELETE RESTRICT ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 9. SUPPORT TICKETS TABLE
DROP TABLE IF EXISTS `support_tickets`;
CREATE TABLE `support_tickets` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `ticket_number` varchar(50) NOT NULL,
  `customer_id` int(11) DEFAULT NULL,
  `subject` varchar(200) NOT NULL,
  `message` text NOT NULL,
  `status` enum('Open','In Progress','Resolved','Closed') DEFAULT 'Open',
  `priority` enum('Low','Medium','High','Urgent') DEFAULT 'Medium',
  `assigned_to` int(11) DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `ticket_number` (`ticket_number`),
  KEY `customer_id` (`customer_id`),
  KEY `assigned_to` (`assigned_to`),
  CONSTRAINT `support_tickets_ibfk_1` FOREIGN KEY (`customer_id`) REFERENCES `customers` (`id`) ON DELETE SET NULL ON UPDATE CASCADE,
  CONSTRAINT `support_tickets_ibfk_2` FOREIGN KEY (`assigned_to`) REFERENCES `admin_users` (`id`) ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 10. SHIPMENT TRACKING TABLE
DROP TABLE IF EXISTS `shipments`;
CREATE TABLE `shipments` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `order_id` int(11) NOT NULL,
  `tracking_number` varchar(100) NOT NULL,
  `courier` varchar(50) DEFAULT NULL,
  `status` enum('Preparing','In Transit','Out for Delivery','Delivered','Returned') DEFAULT 'Preparing',
  `current_location` varchar(200) DEFAULT NULL,
  `estimated_delivery` datetime DEFAULT NULL,
  `actual_delivery` datetime DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `tracking_number` (`tracking_number`),
  KEY `order_id` (`order_id`),
  CONSTRAINT `shipments_ibfk_1` FOREIGN KEY (`order_id`) REFERENCES `orders` (`id`) ON DELETE RESTRICT ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =========================================================================
-- STEP 5: MAGPASOK NG SAMPLE DATA
-- (Ang datos na ito ay kailangan para gumana ang Dashboard at OTP Login)
-- =========================================================================

-- 1. ADMIN USERS
INSERT INTO `admin_users` (`username`, `password_hash`, `role`, `full_name`, `email`, `phone_number`) VALUES
('admin', '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'Admin', 'Administrator', 'admin@imarket.com', '09123456789');
-- Default password: 'password' 

-- 2. CATEGORIES
INSERT INTO `categories` (`name`, `slug`, `description`, `status`) VALUES
('Electronics', 'electronics', 'Electronic devices and accessories', 'Active'),
('Food & Beverage', 'food-beverage', 'Food items and beverages', 'Active'),
('Office Supplies', 'office-supplies', 'Office and stationery items', 'Active'),
('Clothing & Apparel', 'clothing-apparel', 'Clothing and fashion items', 'Active'),
('Home & Living', 'home-living', 'Home decoration and furniture', 'Active');

-- 3. PRODUCTS
INSERT INTO `products` (`name`, `slug`, `description`, `price`, `stock`, `category_id`, `status`, `image_url`) VALUES
('Laptop Pro 2025', 'laptop-pro-2025', 'High-performance laptop for professionals with latest processor', 1200.00, 50, 1, 'Active', NULL),
('Organic Coffee Beans (KG)', 'organic-coffee-beans', 'Single-origin, ethically sourced Arabica beans', 25.50, 12, 2, 'Low Stock', NULL),
('Noise-Cancelling Headphones', 'noise-cancelling-headphones', 'Industry-leading sound quality and comfort', 180.00, 210, 1, 'Active', NULL),
('Ergonomic Desk Mat (Grey)', 'ergonomic-desk-mat', 'Extra large desk mat with anti-slip base', 35.00, 5, 3, 'Critical Stock', NULL),
('Wireless Mouse', 'wireless-mouse', 'Ergonomic wireless mouse with long battery life', 29.99, 85, 1, 'Active', NULL),
('Green Tea (KG)', 'green-tea', 'Premium organic green tea leaves', 18.00, 60, 2, 'Active', NULL),
('Black Tea (KG)', 'black-tea', 'Rich and flavorful black tea', 15.00, 45, 2, 'Active', NULL),
('Premium Notebook Set', 'premium-notebook-set', 'Set of 3 high-quality notebooks', 22.50, 30, 3, 'Active', NULL),
('Standing Desk', 'standing-desk', 'Adjustable height standing desk', 450.00, 12, 3, 'Active', NULL),
('Smart Watch', 'smart-watch', 'Feature-rich smartwatch with health tracking', 299.99, 25, 1, 'Active', NULL);

-- 4. CUSTOMERS
INSERT INTO `customers` (`full_name`, `email`, `phone_number`, `status`) VALUES
('Erica Fernandez', 'erica.fernandez@example.com', '09123456789', 'Active'),
('Jose Perez', 'jose.perez@example.com', '09123456790', 'Active'),
('Anna Martinez', 'anna.martinez@example.com', '09123456791', 'Active'),
('Ramon Torres', 'ramon.torres@example.com', '09123456792', 'Active'),
('Juan Dela Cruz', 'juan.delacruz@example.com', '09123456793', 'Active'),
('Maria Santos', 'maria.santos@example.com', '09123456794', 'Active'),
('Pedro Esguerra', 'pedro.esguerra@example.com', '09123456795', 'Active'),
('Sarah Gomez', 'sarah.gomez@example.com', '09123456796', 'Active');

-- 5. CUSTOMER ADDRESSES
INSERT INTO `customer_addresses` (`customer_id`, `address_line1`, `address_line2`, `city`, `province`, `postal_code`, `country`, `status`, `is_default`) VALUES
(1, '123 Sampaguita St', NULL, 'Quezon City', 'Metro Manila', '1100', 'Philippines', 'Verified', 1),
(2, '456 Maharlika Ave', NULL, 'Cebu City', 'Cebu', '6000', 'Philippines', 'Requires Review', 1),
(3, '789 Kalayaan Rd', NULL, 'Davao City', 'Davao', '8000', 'Philippines', 'Pending Validation', 1),
(4, '321 Rizal Street', NULL, 'Makati City', 'Metro Manila', '1200', 'Philippines', 'Verified', 1),
(5, '654 Bonifacio Ave', NULL, 'Manila', 'Metro Manila', '1000', 'Philippines', 'Verified', 1),
(6, '987 Luna Street', NULL, 'Pasig City', 'Metro Manila', '1600', 'Philippines', 'Verified', 1),
(7, '147 Magallanes St', NULL, 'Iloilo City', 'Iloilo', '5000', 'Philippines', 'Pending Validation', 1),
(8, '258 Garcia Street', NULL, 'Baguio City', 'Benguet', '2600', 'Philippines', 'Verified', 1);

-- 6. ORDERS
INSERT INTO `orders` (`order_number`, `customer_id`, `address_id`, `total_amount`, `status`, `payment_status`, `order_date`, `shipped_date`, `delivered_date`, `notes`) VALUES
('ORD-2025-5001', 1, 1, 202.50, 'Pending', 'Pending', '2025-01-27 10:30:00', NULL, NULL, NULL),
('ORD-2025-5002', 2, 2, 1200.00, 'Processing', 'Paid', '2025-01-27 11:15:00', NULL, NULL, NULL),
('ORD-2025-5003', 3, 3, 68.00, 'Shipped', 'Paid', '2025-01-26 14:20:00', '2025-01-27 08:00:00', NULL, NULL),
('ORD-2025-5004', 4, 4, 450.00, 'Cancelled', 'Refunded', '2025-01-25 09:45:00', NULL, NULL, 'Customer cancelled order'),
('ORD-2025-5005', 5, 5, 211.50, 'Processing', 'Paid', '2025-01-28 08:30:00', NULL, NULL, NULL),
('ORD-2025-5006', 6, 6, 299.99, 'Shipped', 'Paid', '2025-01-27 16:45:00', '2025-01-28 10:00:00', NULL, NULL);

-- 7. ORDER ITEMS
INSERT INTO `order_items` (`order_id`, `product_id`, `quantity`, `price`, `subtotal`) VALUES
(1, 3, 1, 180.00, 180.00),
(1, 8, 1, 22.50, 22.50),
(2, 1, 1, 1200.00, 1200.00),
(3, 6, 1, 18.00, 18.00),
(3, 7, 1, 15.00, 15.00),
(3, 4, 1, 35.00, 35.00),
(4, 9, 1, 450.00, 450.00),
(5, 2, 5, 25.50, 127.50),
(5, 6, 3, 18.00, 54.00),
(5, 7, 2, 15.00, 30.00),
(6, 10, 1, 299.99, 299.99);

-- 8. TRANSACTIONS
INSERT INTO `transactions` (`order_id`, `transaction_number`, `payment_method`, `amount`, `status`, `transaction_date`, `notes`) VALUES
(1, 'TXN-2025-1001', 'Credit Card', 202.50, 'Pending', '2025-01-27 10:30:00', NULL),
(2, 'TXN-2025-1002', 'Bank Transfer', 1200.00, 'Completed', '2025-01-27 11:20:00', NULL),
(3, 'TXN-2025-1003', 'E-Wallet', 68.00, 'Completed', '2025-01-26 14:25:00', NULL),
(4, 'TXN-2025-1004', 'Credit Card', 450.00, 'Refunded', '2025-01-25 09:50:00', 'Refund processed due to cancellation'),
(5, 'TXN-2025-1005', 'Debit Card', 211.50, 'Completed', '2025-01-28 08:35:00', NULL),
(6, 'TXN-2025-1006', 'E-Wallet', 299.99, 'Completed', '2025-01-27 16:50:00', NULL);

-- 9. SUPPORT TICKETS
INSERT INTO `support_tickets` (`ticket_number`, `customer_id`, `subject`, `message`, `status`, `priority`, `assigned_to`) VALUES
('TKT-2025-001', 1, 'Order Delivery Delay', 'My order ORD-2025-5001 was supposed to arrive yesterday but it hasn''t been delivered yet.', 'Open', 'Medium', NULL),
('TKT-2025-002', 3, 'Product Quality Issue', 'The green tea I received seems to be of lower quality than expected.', 'In Progress', 'High', 1),
('TKT-2025-003', 5, 'Payment Refund Request', 'I need to cancel my order and get a refund. Order number: ORD-2025-5005', 'Open', 'Low', NULL),
('TKT-2025-004', 7, 'Account Access Problem', 'I cannot log in to my account. Please help reset my password.', 'Resolved', 'Medium', 1);

-- 10. SHIPMENTS
INSERT INTO `shipments` (`order_id`, `tracking_number`, `courier`, `status`, `current_location`, `estimated_delivery`) VALUES
(2, 'TRK-2025-2001', 'LBC', 'In Transit', 'Manila Sorting Facility', '2025-01-30 14:00:00'),
(3, 'TRK-2025-2002', 'J&T Express', 'Out for Delivery', 'Davao Distribution Center', '2025-01-29 16:00:00'),
(6, 'TRK-2025-2003', 'Grab Express', 'In Transit', 'Pasig Hub', '2025-01-30 10:00:00');

-- =========================================================================
-- STEP 6: I-RE-ENABLE ANG FOREIGN KEY CHECKS
-- =========================================================================
SET FOREIGN_KEY_CHECKS = 1;

-- =========================================================================
-- SETUP COMPLETE!
-- =========================================================================
-- Default Admin Login:
-- Username: admin
-- Password: password
-- 
-- IMPORTANT: Change the default password immediately after first login!
-- =========================================================================