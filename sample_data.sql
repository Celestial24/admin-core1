-- =========================================================================
-- iMARKET Admin Portal - Sample Data
-- =========================================================================
-- Description: Sample data for testing and demonstration
-- Version: 2.0 (Improved and Fixed)
-- =========================================================================

USE `core1`;

-- Disable foreign key checks temporarily for data insertion
SET FOREIGN_KEY_CHECKS = 0;

-- =========================================================================
-- 1. ADMIN USERS (Default admin account for testing)
-- =========================================================================
INSERT INTO `admin_users` (`username`, `password_hash`, `role`, `full_name`, `email`, `phone_number`) VALUES
('admin', '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'Admin', 'Administrator', 'admin@imarket.com', '09123456789');
-- Default password: 'password' (CHANGE THIS IN PRODUCTION!)

-- =========================================================================
-- 2. CATEGORIES
-- =========================================================================
INSERT INTO `categories` (`name`, `slug`, `description`, `status`) VALUES
('Electronics', 'electronics', 'Electronic devices and accessories', 'Active'),
('Food & Beverage', 'food-beverage', 'Food items and beverages', 'Active'),
('Office Supplies', 'office-supplies', 'Office and stationery items', 'Active'),
('Clothing & Apparel', 'clothing-apparel', 'Clothing and fashion items', 'Active'),
('Home & Living', 'home-living', 'Home decoration and furniture', 'Active');

-- =========================================================================
-- 3. PRODUCTS
-- =========================================================================
-- Note: category_id references categories.id (1=Electronics, 2=Food & Beverage, 3=Office Supplies, etc.)
INSERT INTO `products` (`name`, `slug`, `description`, `price`, `stock`, `category_id`, `status`, `image_url`) VALUES
('Laptop Pro 2025', 'laptop-pro-2025', 'High-performance laptop for professionals with latest processor and 16GB RAM', 1200.00, 50, 1, 'Active', NULL),
('Organic Coffee Beans (KG)', 'organic-coffee-beans', 'Single-origin, ethically sourced Arabica beans from premium farms', 25.50, 12, 2, 'Low Stock', NULL),
('Noise-Cancelling Headphones', 'noise-cancelling-headphones', 'Industry-leading sound quality and comfort with 30-hour battery', 180.00, 210, 1, 'Active', NULL),
('Ergonomic Desk Mat (Grey)', 'ergonomic-desk-mat', 'Extra large desk mat with anti-slip base and wrist support', 35.00, 5, 3, 'Critical Stock', NULL),
('Wireless Mouse', 'wireless-mouse', 'Ergonomic wireless mouse with long battery life and precision tracking', 29.99, 85, 1, 'Active', NULL),
('Green Tea (KG)', 'green-tea', 'Premium organic green tea leaves with antioxidant benefits', 18.00, 60, 2, 'Active', NULL),
('Black Tea (KG)', 'black-tea', 'Rich and flavorful black tea perfect for mornings', 15.00, 45, 2, 'Active', NULL),
('Premium Notebook Set', 'premium-notebook-set', 'Set of 3 high-quality notebooks with premium paper', 22.50, 30, 3, 'Active', NULL),
('Standing Desk', 'standing-desk', 'Adjustable height standing desk for ergonomic workspace', 450.00, 12, 3, 'Active', NULL),
('Smart Watch', 'smart-watch', 'Feature-rich smartwatch with health tracking and notifications', 299.99, 25, 1, 'Active', NULL),
('Mechanical Keyboard', 'mechanical-keyboard', 'RGB backlit mechanical keyboard with blue switches', 89.99, 40, 1, 'Active', NULL),
('USB-C Hub', 'usb-c-hub', 'Multi-port USB-C hub with HDMI, USB 3.0, and SD card reader', 45.00, 75, 1, 'Active', NULL),
('Organic Honey (500g)', 'organic-honey-500g', 'Pure organic honey from local beekeepers', 12.99, 35, 2, 'Active', NULL),
('Dark Chocolate Bar', 'dark-chocolate-bar', 'Premium 70% dark chocolate bar with almonds', 8.50, 90, 2, 'Active', NULL),
('Desk Organizer', 'desk-organizer', 'Modern desk organizer with multiple compartments', 28.00, 22, 3, 'Active', NULL),
('Leather Office Chair', 'leather-office-chair', 'Ergonomic leather office chair with lumbar support', 350.00, 8, 3, 'Low Stock', NULL),
('Cotton T-Shirt', 'cotton-t-shirt', 'Premium 100% cotton t-shirt in various colors', 24.99, 55, 4, 'Active', NULL),
('Denim Jeans', 'denim-jeans', 'Classic fit denim jeans with stretch comfort', 59.99, 30, 4, 'Active', NULL),
('Decorative Pillow Set', 'decorative-pillow-set', 'Set of 2 decorative pillows for home decoration', 35.00, 18, 5, 'Active', NULL),
('Table Lamp', 'table-lamp', 'Modern LED table lamp with dimmer control', 42.00, 15, 5, 'Active', NULL),
('Bluetooth Speaker', 'bluetooth-speaker', 'Portable wireless speaker with 20-hour battery life', 79.99, 42, 1, 'Active', NULL),
('Wireless Earbuds', 'wireless-earbuds', 'True wireless earbuds with noise cancellation', 129.99, 38, 1, 'Active', NULL),
('Webcam HD', 'webcam-hd', '1080p HD webcam with built-in microphone', 65.00, 28, 1, 'Active', NULL),
('Monitor Stand', 'monitor-stand', 'Adjustable aluminum monitor stand with storage', 55.00, 19, 3, 'Active', NULL),
('Cable Management Kit', 'cable-management-kit', 'Complete cable organization solution', 18.99, 52, 3, 'Active', NULL),
('Espresso Machine', 'espresso-machine', 'Professional-grade espresso machine for home use', 450.00, 6, 2, 'Low Stock', NULL),
('Tea Infuser Set', 'tea-infuser-set', 'Premium stainless steel tea infuser set', 24.99, 33, 2, 'Active', NULL),
('Running Shoes', 'running-shoes', 'Lightweight running shoes with cushioned sole', 89.99, 47, 4, 'Active', NULL),
('Backpack', 'backpack', 'Durable laptop backpack with multiple compartments', 65.00, 31, 4, 'Active', NULL),
('Wall Clock', 'wall-clock', 'Modern minimalist wall clock with silent mechanism', 35.00, 24, 5, 'Active', NULL);

-- =========================================================================
-- 4. CUSTOMERS
-- =========================================================================
INSERT INTO `customers` (`full_name`, `email`, `phone_number`, `status`) VALUES
('Erica Fernandez', 'erica.fernandez@example.com', '09123456789', 'Active'),
('Jose Perez', 'jose.perez@example.com', '09123456790', 'Active'),
('Anna Martinez', 'anna.martinez@example.com', '09123456791', 'Active'),
('Ramon Torres', 'ramon.torres@example.com', '09123456792', 'Active'),
('Juan Dela Cruz', 'juan.delacruz@example.com', '09123456793', 'Active'),
('Maria Santos', 'maria.santos@example.com', '09123456794', 'Active'),
('Pedro Esguerra', 'pedro.esguerra@example.com', '09123456795', 'Active'),
('Sarah Gomez', 'sarah.gomez@example.com', '09123456796', 'Active'),
('Michael Rodriguez', 'michael.rodriguez@example.com', '09123456797', 'Active'),
('Lisa Garcia', 'lisa.garcia@example.com', '09123456798', 'Active'),
('David Chen', 'david.chen@example.com', '09123456799', 'Active'),
('Jennifer Lee', 'jennifer.lee@example.com', '09123456800', 'Active'),
('Robert Wilson', 'robert.wilson@example.com', '09123456801', 'Active'),
('Amanda Brown', 'amanda.brown@example.com', '09123456802', 'Active');

-- =========================================================================
-- 5. CUSTOMER ADDRESSES
-- =========================================================================
-- Note: customer_id references customers.id (1=Erica, 2=Jose, 3=Anna, etc.)
INSERT INTO `customer_addresses` (`customer_id`, `address_line1`, `address_line2`, `city`, `province`, `postal_code`, `country`, `status`, `is_default`) VALUES
(1, '123 Sampaguita St', NULL, 'Quezon City', 'Metro Manila', '1100', 'Philippines', 'Verified', 1),
(2, '456 Maharlika Ave', NULL, 'Cebu City', 'Cebu', '6000', 'Philippines', 'Requires Review', 1),
(3, '789 Kalayaan Rd', NULL, 'Davao City', 'Davao', '8000', 'Philippines', 'Pending Validation', 1),
(4, '321 Rizal Street', NULL, 'Makati City', 'Metro Manila', '1200', 'Philippines', 'Verified', 1),
(5, '654 Bonifacio Ave', NULL, 'Manila', 'Metro Manila', '1000', 'Philippines', 'Verified', 1),
(6, '987 Luna Street', NULL, 'Pasig City', 'Metro Manila', '1600', 'Philippines', 'Verified', 1),
(7, '147 Magallanes St', NULL, 'Iloilo City', 'Iloilo', '5000', 'Philippines', 'Pending Validation', 1),
(8, '258 Garcia Street', NULL, 'Baguio City', 'Benguet', '2600', 'Philippines', 'Verified', 1),
(9, '369 Ayala Avenue', 'Unit 12B', 'Makati City', 'Metro Manila', '1200', 'Philippines', 'Verified', 1),
(10, '741 Ortigas Avenue', NULL, 'Mandaluyong City', 'Metro Manila', '1550', 'Philippines', 'Verified', 1),
(11, '852 EDSA', 'Block 5', 'Quezon City', 'Metro Manila', '1100', 'Philippines', 'Requires Review', 1),
(12, '963 Taft Avenue', NULL, 'Manila', 'Metro Manila', '1000', 'Philippines', 'Verified', 1),
(13, '159 Roxas Boulevard', NULL, 'Pasay City', 'Metro Manila', '1300', 'Philippines', 'Pending Validation', 1),
(14, '357 Shaw Boulevard', 'Building C', 'Mandaluyong City', 'Metro Manila', '1550', 'Philippines', 'Verified', 1);

-- =========================================================================
-- 6. ORDERS
-- =========================================================================
-- Note: customer_id and address_id must reference existing records
INSERT INTO `orders` (`order_number`, `customer_id`, `address_id`, `total_amount`, `status`, `payment_status`, `order_date`, `shipped_date`, `delivered_date`, `notes`) VALUES
('ORD-2025-5001', 1, 1, 202.50, 'Pending', 'Pending', '2025-01-27 10:30:00', NULL, NULL, NULL),
('ORD-2025-5002', 2, 2, 1200.00, 'Processing', 'Paid', '2025-01-27 11:15:00', NULL, NULL, NULL),
('ORD-2025-5003', 3, 3, 68.00, 'Shipped', 'Paid', '2025-01-26 14:20:00', '2025-01-27 08:00:00', NULL, NULL),
('ORD-2025-5004', 4, 4, 450.00, 'Cancelled', 'Refunded', '2025-01-25 09:45:00', NULL, NULL, 'Customer cancelled order'),
('ORD-2025-5005', 5, 5, 211.50, 'Processing', 'Paid', '2025-01-28 08:30:00', NULL, NULL, NULL),
('ORD-2025-5006', 6, 6, 299.99, 'Shipped', 'Paid', '2025-01-27 16:45:00', '2025-01-28 10:00:00', NULL, NULL),
('ORD-2025-5007', 7, 7, 89.99, 'Delivered', 'Paid', '2025-01-24 09:00:00', '2025-01-25 10:00:00', '2025-01-26 14:30:00', NULL),
('ORD-2025-5008', 8, 8, 134.99, 'Processing', 'Paid', '2025-01-28 12:00:00', NULL, NULL, NULL),
('ORD-2025-5009', 9, 9, 45.00, 'Shipped', 'Paid', '2025-01-27 15:30:00', '2025-01-28 09:00:00', NULL, NULL),
('ORD-2025-5010', 10, 10, 77.50, 'Pending', 'Pending', '2025-01-28 16:00:00', NULL, NULL, NULL),
('ORD-2025-5011', 11, 11, 350.00, 'Processing', 'Paid', '2025-01-28 10:00:00', NULL, NULL, NULL),
('ORD-2025-5012', 12, 12, 84.99, 'Shipped', 'Paid', '2025-01-27 11:00:00', '2025-01-28 08:00:00', NULL, NULL),
('ORD-2025-5013', 13, 13, 180.00, 'Pending', 'Pending', '2025-01-28 17:00:00', NULL, NULL, NULL),
('ORD-2025-5014', 14, 14, 299.99, 'Processing', 'Paid', '2025-01-28 13:00:00', NULL, NULL, NULL),
('ORD-2025-5015', 1, 1, 45.00, 'Delivered', 'Paid', '2025-01-23 10:00:00', '2025-01-24 09:00:00', '2025-01-25 15:00:00', NULL),
('ORD-2025-5016', 3, 3, 127.50, 'Shipped', 'Paid', '2025-01-27 09:00:00', '2025-01-28 08:00:00', NULL, NULL),
('ORD-2025-5017', 5, 5, 89.99, 'Processing', 'Paid', '2025-01-28 14:00:00', NULL, NULL, NULL),
('ORD-2025-5018', 7, 7, 35.00, 'Pending', 'Pending', '2025-01-28 18:00:00', NULL, NULL, NULL);

-- =========================================================================
-- 7. ORDER ITEMS
-- =========================================================================
-- Note: order_id references orders.id, product_id references products.id
-- Fixing the subtotals to match quantity * price
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
(6, 10, 1, 299.99, 299.99),
(7, 11, 1, 89.99, 89.99),
(8, 10, 1, 299.99, 299.99),
(8, 13, 1, 12.99, 12.99),
(8, 14, 1, 8.50, 8.50),
(9, 12, 1, 45.00, 45.00),
(10, 17, 2, 24.99, 49.98),
(10, 18, 1, 59.99, 59.99),
(11, 16, 1, 350.00, 350.00),
(12, 11, 1, 89.99, 89.99),
(12, 5, 1, 29.99, 29.99),
(13, 3, 1, 180.00, 180.00),
(14, 10, 1, 299.99, 299.99),
(15, 12, 1, 45.00, 45.00),
(16, 2, 5, 25.50, 127.50),
(17, 11, 1, 89.99, 89.99),
(18, 4, 1, 35.00, 35.00);

-- =========================================================================
-- 8. TRANSACTIONS
-- =========================================================================
-- Note: order_id references orders.id
INSERT INTO `transactions` (`order_id`, `transaction_number`, `payment_method`, `amount`, `status`, `transaction_date`, `notes`) VALUES
(1, 'TXN-2025-1001', 'Credit Card', 202.50, 'Pending', '2025-01-27 10:30:00', NULL),
(2, 'TXN-2025-1002', 'Bank Transfer', 1200.00, 'Completed', '2025-01-27 11:20:00', NULL),
(3, 'TXN-2025-1003', 'E-Wallet', 68.00, 'Completed', '2025-01-26 14:25:00', NULL),
(4, 'TXN-2025-1004', 'Credit Card', 450.00, 'Refunded', '2025-01-25 09:50:00', 'Refund processed due to cancellation'),
(5, 'TXN-2025-1005', 'Debit Card', 211.50, 'Completed', '2025-01-28 08:35:00', NULL),
(6, 'TXN-2025-1006', 'E-Wallet', 299.99, 'Completed', '2025-01-27 16:50:00', NULL),
(7, 'TXN-2025-1007', 'Credit Card', 89.99, 'Completed', '2025-01-24 09:15:00', NULL),
(8, 'TXN-2025-1008', 'E-Wallet', 134.99, 'Completed', '2025-01-28 12:10:00', NULL),
(9, 'TXN-2025-1009', 'Debit Card', 45.00, 'Completed', '2025-01-27 15:45:00', NULL),
(10, 'TXN-2025-1010', 'Credit Card', 77.50, 'Pending', '2025-01-28 16:05:00', NULL),
(11, 'TXN-2025-1011', 'Bank Transfer', 350.00, 'Completed', '2025-01-28 10:15:00', NULL),
(12, 'TXN-2025-1012', 'E-Wallet', 84.99, 'Completed', '2025-01-27 11:15:00', NULL),
(13, 'TXN-2025-1013', 'Credit Card', 180.00, 'Pending', '2025-01-28 17:05:00', NULL),
(14, 'TXN-2025-1014', 'E-Wallet', 299.99, 'Completed', '2025-01-28 13:10:00', NULL),
(15, 'TXN-2025-1015', 'Debit Card', 45.00, 'Completed', '2025-01-23 10:15:00', NULL),
(16, 'TXN-2025-1016', 'Bank Transfer', 127.50, 'Completed', '2025-01-27 09:15:00', NULL),
(17, 'TXN-2025-1017', 'E-Wallet', 89.99, 'Completed', '2025-01-28 14:10:00', NULL),
(18, 'TXN-2025-1018', 'Credit Card', 35.00, 'Pending', '2025-01-28 18:05:00', NULL);

-- =========================================================================
-- 9. SUPPORT TICKETS
-- =========================================================================
-- Note: customer_id references customers.id, assigned_to references admin_users.id
INSERT INTO `support_tickets` (`ticket_number`, `customer_id`, `subject`, `message`, `status`, `priority`, `assigned_to`) VALUES
('TKT-2025-001', 1, 'Order Delivery Delay', 'My order ORD-2025-5001 was supposed to arrive yesterday but it hasn''t been delivered yet.', 'Open', 'Medium', NULL),
('TKT-2025-002', 3, 'Product Quality Issue', 'The green tea I received seems to be of lower quality than expected.', 'In Progress', 'High', 1),
('TKT-2025-003', 5, 'Payment Refund Request', 'I need to cancel my order and get a refund. Order number: ORD-2025-5005', 'Open', 'Low', NULL),
('TKT-2025-004', 7, 'Account Access Problem', 'I cannot log in to my account. Please help reset my password.', 'Resolved', 'Medium', 1),
('TKT-2025-005', 2, 'Shipping Address Change', 'I need to change the shipping address for my order ORD-2025-5002', 'Open', 'Medium', NULL),
('TKT-2025-006', 9, 'Product Inquiry', 'Do you have the mechanical keyboard in stock? I would like to place an order.', 'Open', 'Low', NULL),
('TKT-2025-007', 11, 'Billing Question', 'I was charged twice for my order. Can you please check?', 'In Progress', 'High', 1),
('TKT-2025-008', 13, 'Return Request', 'I would like to return the table lamp I received. It has a defect.', 'Open', 'Medium', NULL),
('TKT-2025-009', 4, 'Product Availability', 'When will the Laptop Pro 2025 be back in stock?', 'Open', 'Low', NULL),
('TKT-2025-010', 6, 'Order Status Inquiry', 'Can you provide an update on order ORD-2025-5006?', 'Open', 'Low', NULL),
('TKT-2025-011', 8, 'Discount Code Issue', 'My discount code is not working at checkout.', 'In Progress', 'Medium', 1),
('TKT-2025-012', 10, 'Technical Support', 'I need help setting up my smart watch.', 'Resolved', 'Low', 1),
('TKT-2025-013', 12, 'Delivery Timeframe', 'What is the estimated delivery time for Metro Manila?', 'Open', 'Low', NULL),
('TKT-2025-014', 14, 'Product Recommendation', 'Can you recommend a good wireless mouse?', 'Open', 'Low', NULL);

-- =========================================================================
-- 10. SHIPMENTS
-- =========================================================================
-- Note: order_id references orders.id (only for shipped orders)
INSERT INTO `shipments` (`order_id`, `tracking_number`, `courier`, `status`, `current_location`, `estimated_delivery`) VALUES
(2, 'TRK-2025-2001', 'LBC', 'In Transit', 'Manila Sorting Facility', '2025-01-30 14:00:00'),
(3, 'TRK-2025-2002', 'J&T Express', 'Out for Delivery', 'Davao Distribution Center', '2025-01-29 16:00:00'),
(5, 'TRK-2025-2007', 'LBC', 'Preparing', 'Manila Warehouse', '2025-01-31 10:00:00'),
(6, 'TRK-2025-2003', 'Grab Express', 'In Transit', 'Pasig Hub', '2025-01-30 10:00:00'),
(7, 'TRK-2025-2004', 'LBC', 'Delivered', 'Quezon City', '2025-01-26 14:30:00'),
(8, 'TRK-2025-2008', 'J&T Express', 'Preparing', 'Cebu Warehouse', '2025-02-01 12:00:00'),
(9, 'TRK-2025-2005', 'J&T Express', 'In Transit', 'Cebu Sorting Center', '2025-01-30 12:00:00'),
(11, 'TRK-2025-2009', 'Grab Express', 'Preparing', 'Manila Warehouse', '2025-01-31 16:00:00'),
(12, 'TRK-2025-2006', 'Grab Express', 'Out for Delivery', 'Makati Distribution Center', '2025-01-29 18:00:00');

-- Re-enable foreign key checks
SET FOREIGN_KEY_CHECKS = 1;

-- =========================================================================
-- VERIFICATION QUERIES (Optional - uncomment to verify data)
-- =========================================================================
-- SELECT COUNT(*) as category_count FROM categories;
-- SELECT COUNT(*) as product_count FROM products;
-- SELECT COUNT(*) as customer_count FROM customers;
-- SELECT COUNT(*) as order_count FROM orders;
-- SELECT COUNT(*) as transaction_count FROM transactions;

-- =========================================================================
-- END OF SAMPLE DATA
-- =========================================================================
