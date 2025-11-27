<?php
// =========================================================================
// core1admin/functions.php - All Application Logic Functions
// =========================================================================
// This file contains all business logic functions for the admin portal
// All functions expect a PDO connection object as their first parameter
// =========================================================================

// Ensure database connection is available
if (!function_exists('get_db_connection')) {
    require_once 'connection.php';
}

// ===========================================
// HELPER FUNCTIONS FOR DATABASE ACCESS
// ===========================================

/**
 * Get database connection - wrapper function
 * Returns PDO connection object from connection.php
 */
if (!function_exists('get_pdo')) {
function get_pdo() {
    if (function_exists('get_db_connection')) {
        return get_db_connection();
    }
    // Fallback to global if function doesn't exist
    global $pdo;
    if ($pdo === null && isset($GLOBALS['pdo'])) {
        return $GLOBALS['pdo'];
    }
    return $pdo;
}
}

// ===========================================
// MODULE 0: AUTHENTICATION & OTP 
// ===========================================

/**
 * Fetches admin user data by username. Uses prepared statements.
 */
if (!function_exists('get_admin_user_by_username')) {
function get_admin_user_by_username($pdo, $username) {
    try {
        $stmt = $pdo->prepare("SELECT * FROM admin_users WHERE username = ?");
        $stmt->execute([$username]);
        return $stmt->fetch(PDO::FETCH_ASSOC);
    } catch (PDOException $e) {
        error_log("Database Error in get_admin_user_by_username: " . $e->getMessage());
        return false;
    }
}
}

/**
 * Fetches admin user profile details by ID, including phone_number.
 */
if (!function_exists('get_admin_user_details')) {
function get_admin_user_details($pdo, $id) {
    try {
        $stmt = $pdo->prepare("SELECT id, username, role, full_name, email, phone_number, password_hash, otp_code, otp_expiry FROM admin_users WHERE id = ?");
        $stmt->execute([$id]);
        return $stmt->fetch(PDO::FETCH_ASSOC);
    } catch (PDOException $e) {
        error_log("Database Error in get_admin_user_details: " . $e->getMessage());
        return false;
    }
}
}

/**
 * Generates a 6-digit cryptographically secure OTP.
 */
if (!function_exists('generate_otp')) {
function generate_otp() {
    return strval(random_int(100000, 999999));
}
}

/**
 * Saves the OTP and expiry time (5 minutes) to the database.
 */
if (!function_exists('save_otp')) {
function save_otp($pdo, $user_id, $otp) {
    $expiry = date('Y-m-d H:i:s', time() + 300); // 300 seconds (5 minutes)
    try {
        // [SECURITY: USING PREPARED STATEMENT]
        $stmt = $pdo->prepare("UPDATE admin_users SET otp_code = ?, otp_expiry = ? WHERE id = ?");
        $stmt->execute([$otp, $expiry, $user_id]);
        return true;
    } catch (PDOException $e) {
        error_log("Database Error in save_otp: " . $e->getMessage());
        return false;
    }
}
}

/**
 * Simulates sending the OTP via Email to the provided email address.
 */
if (!function_exists('simulate_send_otp')) {
function simulate_send_otp($email, $otp) {
    error_log("SIMULATED OTP SEND to {$email} (EMAIL): CODE is {$otp}");
    return "The OTP code has been sent to your email address **{$email} (Gmail)**. **(DEMO CODE: {$otp})**";
}
}

/**
 * PHASE 1: Authenticates the user and initiates OTP via Email.
 */
if (!function_exists('authenticate_admin')) {
function authenticate_admin($pdo, $username, $password) {
    $user = get_admin_user_by_username($pdo, $username);

    if ($user && password_verify($password, $user['password_hash'])) {
        if (empty($user['email'])) {
            return ['success' => false, 'message' => "Login failed: No registered email address for OTP."];
        }

        $otp = generate_otp();
        $recipient = $user['email']; 
        
        if (save_otp($pdo, $user['id'], $otp)) {
            $otp_message = simulate_send_otp($recipient, $otp);
            
            // Set temporary session for OTP validation
            $_SESSION['admin_awaiting_otp'] = true;
            $_SESSION['temp_admin_id'] = $user['id'];
            $_SESSION['temp_admin_username'] = $user['username'];
            
            return [
                'success' => true, 
                'redirect_view' => 'otp', 
                'message' => $otp_message
            ];
        } else {
            return ['success' => false, 'message' => "Login failed: Could not save OTP. Please check database permissions and column names."];
        }
    } else {
        return ['success' => false, 'message' => "Login failed: Incorrect username or password."];
    }
}
}

/**
 * PHASE 2: Verifies the entered OTP and completes login.
 */
if (!function_exists('verify_otp_and_login')) {
function verify_otp_and_login($pdo, $user_id, $otp_input) {
    $user = get_admin_user_details($pdo, $user_id);
    
    if (!$user) {
        return "Error: User data not found during OTP check.";
    }

    if (empty($user['otp_code'])) {
         return "Error: OTP expired or not generated. Please login again.";
    }

    $current_time = new DateTime();
    $expiry_time = new DateTime($user['otp_expiry']);

    // 1. Check if OTP matches
    if ($user['otp_code'] !== $otp_input) {
        return "Invalid OTP. Please try again.";
    }

    // 2. Check if OTP has expired
    if ($current_time > $expiry_time) {
        $pdo->prepare("UPDATE admin_users SET otp_code = NULL, otp_expiry = NULL WHERE id = ?")->execute([$user_id]);
        return "OTP expired. Please log in again to generate a new code.";
    }

    // OTP is valid! Clear the OTP fields and log in.
    $pdo->prepare("UPDATE admin_users SET otp_code = NULL, otp_expiry = NULL WHERE id = ?")->execute([$user_id]);
    
    $_SESSION['admin_logged_in'] = true;
    $_SESSION['admin_id'] = $user['id'];
    $_SESSION['admin_username'] = $user['username'];
    $_SESSION['admin_role'] = $user['role'];
    
    unset($_SESSION['admin_awaiting_otp']);
    unset($_SESSION['temp_admin_id']);
    unset($_SESSION['temp_admin_username']);
    
    return "Successful login! Welcome, " . $user['username'] . ".";
}
}


/**
 * Creates a new admin user account.
 */
if (!function_exists('create_admin_account')) {
function create_admin_account($pdo, $username, $password, $email, $phone_number, $full_name) {
    $role = 'Admin';
    
    if (strlen($password) < 6) {
        return "Registration failed: Password must be at least 6 characters long.";
    }
    if (get_admin_user_by_username($pdo, $username)) {
        return "Registration failed: Username is already taken.";
    }

    $password_hash = password_hash($password, PASSWORD_BCRYPT);

    try {
        // [SECURITY: USING PREPARED STATEMENT]
        $stmt = $pdo->prepare("INSERT INTO admin_users (username, password_hash, role, email, phone_number, full_name) VALUES (?, ?, ?, ?, ?, ?)");
        $stmt->execute([$username, $password_hash, $role, $email, $phone_number, $full_name]);
        
        // Retrieve the ID of the newly created user for OTP initialization
        $user = get_admin_user_by_username($pdo, $username);
        return [
            'success' => true,
            'user_id' => $user['id'],
            'username' => $username,
            'email' => $email, // Used for OTP initialization
            'message' => "Account for '{$username}' successfully created. Now, OTP verification is required."
        ];
    } catch (PDOException $e) {
        error_log("Database Error in create_admin_account: " . $e->getMessage());
        return ['success' => false, 'message' => "Registration failed due to a database error. Please ensure 'phone_number', 'full_name', 'otp_code', and 'otp_expiry' columns exist."];
    }
}
}

/**
 * Function to handle redirect back to Login/Register from OTP screen.
 */
if (!function_exists('handle_login_redirect')) {
function handle_login_redirect() {
    // Clear temporary session data
    unset($_SESSION['admin_awaiting_otp']);
    unset($_SESSION['temp_admin_id']);
    unset($_SESSION['temp_admin_username']);
    
    // Redirect to main page (login view)
    header("Location: " . basename(__FILE__) . "?msg=" . urlencode("Your session has been cleared. Log in again to generate a new OTP."));
    exit();
}
}

if (!function_exists('handle_logout')) {
function handle_logout() {
    $_SESSION = array();
    if (ini_get("session.use_cookies")) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000, $params["path"], $params["domain"], $params["secure"], $params["httponly"]);
    }
    session_destroy();
    header("Location: " . basename(__FILE__) . "?msg=" . urlencode("Successfully logged out."));
    exit();
}
}

/**
 * Handles profile updates, including phone_number.
 */
if (!function_exists('update_admin_profile')) {
function update_admin_profile($pdo, $id, $new_username, $full_name, $email, $phone_number, $current_password, $new_password = null) {
    $user = get_admin_user_details($pdo, $id);
    
    if (!$user || !password_verify($current_password, $user['password_hash'])) {
        return "Profile update failed: Invalid current password.";
    }

    $fields_to_update = ["username = ?", "full_name = ?", "email = ?", "phone_number = ?"];
    $params = [$new_username, $full_name, $email, $phone_number];
    $message = "Profile details successfully updated!";

    if (!empty($new_password)) {
        if (strlen($new_password) < 6) {
             return "Profile update failed: New password must be at least 6 characters long.";
        }
        $password_hash = password_hash($new_password, PASSWORD_BCRYPT);
        $fields_to_update[] = "password_hash = ?";
        $params[] = $password_hash;
        $message = "Profile and password successfully updated!";
    }

    $update_query = "UPDATE admin_users SET " . implode(", ", $fields_to_update) . " WHERE id = ?";
    $params[] = $id;

    try {
        $stmt = $pdo->prepare($update_query);
        $stmt->execute($params);
        $_SESSION['admin_username'] = $new_username;

        return $message;
    } catch (PDOException $e) {
        error_log("Database Error in update_admin_profile: " . $e->getMessage());
        return "Profile update failed due to a database error.";
    }
}
}

// ===========================================
// MODULE 1: PRODUCTS MANAGEMENT
// ===========================================

/**
 * Get all products with category information
 */
if (!function_exists('get_products_list')) {
function get_products_list($pdo = null) {
    if ($pdo === null) {
        $pdo = get_pdo();
    }
    if (!$pdo) return [];
    try {
        $stmt = $pdo->prepare("
            SELECT p.*, c.name as category 
            FROM products p 
            LEFT JOIN categories c ON p.category_id = c.id 
            ORDER BY p.id DESC
        ");
        $stmt->execute();
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    } catch (PDOException $e) {
        error_log("Database Error in get_products_list: " . $e->getMessage());
        return [];
    }
}
}

/**
 * Get all categories
 */
if (!function_exists('get_categories_list')) {
function get_categories_list($pdo = null) {
    if ($pdo === null) {
        $pdo = get_pdo();
    }
    if (!$pdo) return [];
    try {
        $stmt = $pdo->prepare("SELECT * FROM categories WHERE status = 'Active' ORDER BY name");
        $stmt->execute();
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    } catch (PDOException $e) {
        error_log("Database Error in get_categories_list: " . $e->getMessage());
        return [];
    }
}
}

// ===========================================
// MODULE 2: ORDERS MANAGEMENT
// ===========================================

/**
 * Get all orders with customer information
 */
if (!function_exists('get_orders_list')) {
function get_orders_list($pdo = null) {
    if ($pdo === null) {
        $pdo = get_pdo();
    }
    if (!$pdo) return [];
    try {
        $stmt = $pdo->prepare("
            SELECT o.id, o.order_number, o.total_amount as total, o.status, o.order_date as date, 
                   c.full_name as customer,
                   (SELECT COUNT(*) FROM order_items WHERE order_id = o.id) as items
            FROM orders o 
            LEFT JOIN customers c ON o.customer_id = c.id 
            ORDER BY o.order_date DESC
        ");
        $stmt->execute();
        $orders = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        // Format for display
        $formatted = [];
        foreach ($orders as $order) {
            $formatted[] = [
                'id' => $order['id'],
                'customer' => $order['customer'] ?? 'N/A',
                'total' => floatval($order['total']),
                'status' => $order['status'],
                'date' => date('Y-m-d', strtotime($order['date'])),
                'items' => intval($order['items'])
            ];
        }
        return $formatted;
    } catch (PDOException $e) {
        error_log("Database Error in get_orders_list: " . $e->getMessage());
        return [];
    }
}
}

/**
 * Update order status
 */
if (!function_exists('update_order_status')) {
function update_order_status($order_id, $new_status, $pdo = null) {
    if ($pdo === null) {
        $pdo = get_pdo();
    }
    if (!$pdo) return false;
    try {
        $stmt = $pdo->prepare("UPDATE orders SET status = ?, updated_at = NOW() WHERE id = ?");
        $stmt->execute([$new_status, $order_id]);
        return true;
    } catch (PDOException $e) {
        error_log("Database Error in update_order_status: " . $e->getMessage());
        return false;
    }
}
}

// ===========================================
// MODULE 3: CUSTOMERS MANAGEMENT (Addresses)
// ===========================================

/**
 * Get customer addresses
 */
if (!function_exists('get_customer_addresses')) {
function get_customer_addresses($pdo = null) {
    if ($pdo === null) {
        $pdo = get_pdo();
    }
    if (!$pdo) return [];
    try {
        $stmt = $pdo->prepare("
            SELECT ca.id, ca.address_line1, ca.address_line2, ca.city, ca.province, ca.status,
                   c.full_name as customer_name
            FROM customer_addresses ca 
            LEFT JOIN customers c ON ca.customer_id = c.id 
            ORDER BY ca.created_at DESC
        ");
        $stmt->execute();
        $addresses = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        // Format addresses for display
        $formatted = [];
        foreach ($addresses as $addr) {
            $formatted[] = [
                'id' => 'ADD-' . $addr['id'],
                'customer' => $addr['customer_name'] ?? 'N/A',
                'address' => $addr['address_line1'] . 
                            ($addr['address_line2'] ? ', ' . $addr['address_line2'] : '') . 
                            ', ' . $addr['city'] . ', ' . $addr['province'],
                'status' => $addr['status']
            ];
        }
        return $formatted;
    } catch (PDOException $e) {
        error_log("Database Error in get_customer_addresses: " . $e->getMessage());
        return [];
    }
}
}

// ===========================================
// PRODUCT CRUD OPERATIONS
// ===========================================

/**
 * Add a new product
 */
if (!function_exists('add_product')) {
function add_product($pdo, $name, $slug, $description, $price, $stock, $category_id, $status = 'Active', $image_url = null) {
    try {
        $stmt = $pdo->prepare("INSERT INTO products (name, slug, description, price, stock, category_id, status, image_url) VALUES (?, ?, ?, ?, ?, ?, ?, ?)");
        $stmt->execute([$name, $slug, $description, $price, $stock, $category_id, $status, $image_url]);
        return ['success' => true, 'message' => 'Product added successfully', 'id' => $pdo->lastInsertId()];
    } catch (PDOException $e) {
        error_log("Database Error in add_product: " . $e->getMessage());
        return ['success' => false, 'message' => 'Failed to add product: ' . $e->getMessage()];
    }
}
}

/**
 * Update a product
 */
if (!function_exists('update_product')) {
function update_product($pdo, $id, $name, $slug, $description, $price, $stock, $category_id, $status, $image_url = null) {
    try {
        $stmt = $pdo->prepare("UPDATE products SET name = ?, slug = ?, description = ?, price = ?, stock = ?, category_id = ?, status = ?, image_url = ?, updated_at = NOW() WHERE id = ?");
        $stmt->execute([$name, $slug, $description, $price, $stock, $category_id, $status, $image_url, $id]);
        return ['success' => true, 'message' => 'Product updated successfully'];
    } catch (PDOException $e) {
        error_log("Database Error in update_product: " . $e->getMessage());
        return ['success' => false, 'message' => 'Failed to update product: ' . $e->getMessage()];
    }
}
}

/**
 * Delete a product
 */
if (!function_exists('delete_product')) {
function delete_product($pdo, $id) {
    try {
        $stmt = $pdo->prepare("DELETE FROM products WHERE id = ?");
        $stmt->execute([$id]);
        return ['success' => true, 'message' => 'Product deleted successfully'];
    } catch (PDOException $e) {
        error_log("Database Error in delete_product: " . $e->getMessage());
        return ['success' => false, 'message' => 'Failed to delete product: ' . $e->getMessage()];
    }
}
}

/**
 * Get product by ID
 */
if (!function_exists('get_product_by_id')) {
function get_product_by_id($pdo, $id) {
    try {
        $stmt = $pdo->prepare("SELECT p.*, c.name as category FROM products p LEFT JOIN categories c ON p.category_id = c.id WHERE p.id = ?");
        $stmt->execute([$id]);
        return $stmt->fetch(PDO::FETCH_ASSOC);
    } catch (PDOException $e) {
        error_log("Database Error in get_product_by_id: " . $e->getMessage());
        return false;
    }
}
}

// ===========================================
// CATEGORY CRUD OPERATIONS
// ===========================================

/**
 * Add a new category
 */
if (!function_exists('add_category')) {
function add_category($pdo, $name, $slug, $description = null, $status = 'Active') {
    try {
        $stmt = $pdo->prepare("INSERT INTO categories (name, slug, description, status) VALUES (?, ?, ?, ?)");
        $stmt->execute([$name, $slug, $description, $status]);
        return ['success' => true, 'message' => 'Category added successfully', 'id' => $pdo->lastInsertId()];
    } catch (PDOException $e) {
        error_log("Database Error in add_category: " . $e->getMessage());
        return ['success' => false, 'message' => 'Failed to add category: ' . $e->getMessage()];
    }
}
}

/**
 * Update a category
 */
if (!function_exists('update_category')) {
function update_category($pdo, $id, $name, $slug, $description = null, $status = 'Active') {
    try {
        $stmt = $pdo->prepare("UPDATE categories SET name = ?, slug = ?, description = ?, status = ?, updated_at = NOW() WHERE id = ?");
        $stmt->execute([$name, $slug, $description, $status, $id]);
        return ['success' => true, 'message' => 'Category updated successfully'];
    } catch (PDOException $e) {
        error_log("Database Error in update_category: " . $e->getMessage());
        return ['success' => false, 'message' => 'Failed to update category: ' . $e->getMessage()];
    }
}
}

/**
 * Delete a category
 */
if (!function_exists('delete_category')) {
function delete_category($pdo, $id) {
    try {
        $stmt = $pdo->prepare("DELETE FROM categories WHERE id = ?");
        $stmt->execute([$id]);
        return ['success' => true, 'message' => 'Category deleted successfully'];
    } catch (PDOException $e) {
        error_log("Database Error in delete_category: " . $e->getMessage());
        return ['success' => false, 'message' => 'Failed to delete category: ' . $e->getMessage()];
    }
}
}

/**
 * Get category by ID
 */
if (!function_exists('get_category_by_id')) {
function get_category_by_id($pdo, $id) {
    try {
        $stmt = $pdo->prepare("SELECT * FROM categories WHERE id = ?");
        $stmt->execute([$id]);
        return $stmt->fetch(PDO::FETCH_ASSOC);
    } catch (PDOException $e) {
        error_log("Database Error in get_category_by_id: " . $e->getMessage());
        return false;
    }
}
}

// ===========================================
// TRANSACTIONS MANAGEMENT
// ===========================================

/**
 * Get all transactions
 */
if (!function_exists('get_transactions_list')) {
function get_transactions_list($pdo = null) {
    if ($pdo === null) {
        $pdo = get_pdo();
    }
    if (!$pdo) return [];
    try {
        $stmt = $pdo->prepare("
            SELECT t.*, o.order_number, c.full_name as customer_name
            FROM transactions t
            LEFT JOIN orders o ON t.order_id = o.id
            LEFT JOIN customers c ON o.customer_id = c.id
            ORDER BY t.transaction_date DESC
        ");
        $stmt->execute();
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    } catch (PDOException $e) {
        error_log("Database Error in get_transactions_list: " . $e->getMessage());
        return [];
    }
}
}

// ===========================================
// SHIPMENTS MANAGEMENT
// ===========================================

/**
 * Get all shipments
 */
if (!function_exists('get_shipments_list')) {
function get_shipments_list($pdo = null) {
    if ($pdo === null) {
        $pdo = get_pdo();
    }
    if (!$pdo) return [];
    try {
        $stmt = $pdo->prepare("
            SELECT s.*, o.order_number, c.full_name as customer_name
            FROM shipments s
            LEFT JOIN orders o ON s.order_id = o.id
            LEFT JOIN customers c ON o.customer_id = c.id
            ORDER BY s.created_at DESC
        ");
        $stmt->execute();
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    } catch (PDOException $e) {
        error_log("Database Error in get_shipments_list: " . $e->getMessage());
        return [];
    }
}
}

// ===========================================
// CUSTOMERS MANAGEMENT
// ===========================================

/**
 * Get all customers
 */
if (!function_exists('get_customers_list')) {
function get_customers_list($pdo = null) {
    if ($pdo === null) {
        $pdo = get_pdo();
    }
    if (!$pdo) return [];
    try {
        $stmt = $pdo->prepare("
            SELECT c.*, 
                   (SELECT COUNT(*) FROM orders WHERE customer_id = c.id) as total_orders,
                   (SELECT SUM(total_amount) FROM orders WHERE customer_id = c.id AND status != 'Cancelled') as total_spent
            FROM customers c
            ORDER BY c.created_at DESC
        ");
        $stmt->execute();
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    } catch (PDOException $e) {
        error_log("Database Error in get_customers_list: " . $e->getMessage());
        return [];
    }
}
}

// ===========================================
// SUPPORT TICKETS MANAGEMENT
// ===========================================

/**
 * Get all support tickets
 */
if (!function_exists('get_support_tickets_list')) {
function get_support_tickets_list($pdo = null) {
    if ($pdo === null) {
        $pdo = get_pdo();
    }
    if (!$pdo) return [];
    try {
        $stmt = $pdo->prepare("
            SELECT st.*, c.full_name as customer_name, c.email as customer_email,
                   a.username as assigned_admin
            FROM support_tickets st
            LEFT JOIN customers c ON st.customer_id = c.id
            LEFT JOIN admin_users a ON st.assigned_to = a.id
            ORDER BY st.created_at DESC
        ");
        $stmt->execute();
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    } catch (PDOException $e) {
        error_log("Database Error in get_support_tickets_list: " . $e->getMessage());
        return [];
    }
}
}

/**
 * Update support ticket
 */
if (!function_exists('update_support_ticket')) {
function update_support_ticket($pdo, $id, $status, $priority = null, $assigned_to = null) {
    try {
        $fields = ["status = ?"];
        $params = [$status];
        
        if ($priority !== null) {
            $fields[] = "priority = ?";
            $params[] = $priority;
        }
        
        if ($assigned_to !== null) {
            $fields[] = "assigned_to = ?";
            $params[] = $assigned_to;
        }
        
        $fields[] = "updated_at = NOW()";
        $params[] = $id;
        
        $stmt = $pdo->prepare("UPDATE support_tickets SET " . implode(", ", $fields) . " WHERE id = ?");
        $stmt->execute($params);
        return ['success' => true, 'message' => 'Ticket updated successfully'];
    } catch (PDOException $e) {
        error_log("Database Error in update_support_ticket: " . $e->getMessage());
        return ['success' => false, 'message' => 'Failed to update ticket: ' . $e->getMessage()];
    }
}
}

// ===========================================
// ADMIN USERS MANAGEMENT
// ===========================================

/**
 * Get all admin users
 */
if (!function_exists('get_admin_users_list')) {
function get_admin_users_list($pdo = null) {
    if ($pdo === null) {
        $pdo = get_pdo();
    }
    if (!$pdo) return [];
    try {
        $stmt = $pdo->prepare("SELECT id, username, role, full_name, email, phone_number, created_at, updated_at FROM admin_users ORDER BY created_at DESC");
        $stmt->execute();
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    } catch (PDOException $e) {
        error_log("Database Error in get_admin_users_list: " . $e->getMessage());
        return [];
    }
}
}

/**
 * Delete admin user
 */
if (!function_exists('delete_admin_user')) {
function delete_admin_user($pdo, $id) {
    try {
        // Prevent deleting the last admin
        $stmt = $pdo->prepare("SELECT COUNT(*) as count FROM admin_users");
        $stmt->execute();
        $result = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if ($result['count'] <= 1) {
            return ['success' => false, 'message' => 'Cannot delete the last admin user'];
        }
        
        $stmt = $pdo->prepare("DELETE FROM admin_users WHERE id = ?");
        $stmt->execute([$id]);
        return ['success' => true, 'message' => 'Admin user deleted successfully'];
    } catch (PDOException $e) {
        error_log("Database Error in delete_admin_user: " . $e->getMessage());
        return ['success' => false, 'message' => 'Failed to delete admin user: ' . $e->getMessage()];
    }
}
}

// ===========================================
// MODULE 7: DASHBOARD KPIs
// ===========================================

/**
 * Get dashboard KPI data from database
 */
if (!function_exists('get_dashboard_kpis')) {
function get_dashboard_kpis($pdo = null) {
    if ($pdo === null) {
        $pdo = get_pdo();
    }
    if (!$pdo) return [
        'totalRevenue' => 0, 'totalOrders' => 0, 'lowStockCount' => 0, 'newCustomers' => 0, 'topProducts' => []
    ];
    try {
        // Total Revenue (from completed transactions this month)
        $stmt = $pdo->prepare("
            SELECT COALESCE(SUM(amount), 0) as total 
            FROM transactions 
            WHERE status = 'Completed' 
            AND MONTH(transaction_date) = MONTH(CURRENT_DATE())
            AND YEAR(transaction_date) = YEAR(CURRENT_DATE())
        ");
        $stmt->execute();
        $revenue = $stmt->fetch(PDO::FETCH_ASSOC);
        $totalRevenue = floatval($revenue['total']);

        // Total Orders (this month)
        $stmt = $pdo->prepare("
            SELECT COUNT(*) as total 
            FROM orders 
            WHERE MONTH(order_date) = MONTH(CURRENT_DATE())
            AND YEAR(order_date) = YEAR(CURRENT_DATE())
        ");
        $stmt->execute();
        $orders = $stmt->fetch(PDO::FETCH_ASSOC);
        $totalOrders = intval($orders['total']);

        // Low Stock Count (stock < 10)
        $stmt = $pdo->prepare("SELECT COUNT(*) as total FROM products WHERE stock < 10 AND status != 'Inactive'");
        $stmt->execute();
        $lowStock = $stmt->fetch(PDO::FETCH_ASSOC);
        $lowStockCount = intval($lowStock['total']);

        // New Customers (this month)
        $stmt = $pdo->prepare("
            SELECT COUNT(*) as total 
            FROM customers 
            WHERE MONTH(created_at) = MONTH(CURRENT_DATE())
            AND YEAR(created_at) = YEAR(CURRENT_DATE())
        ");
        $stmt->execute();
        $customers = $stmt->fetch(PDO::FETCH_ASSOC);
        $newCustomers = intval($customers['total']);

        // Top Products (by order items sold)
        $stmt = $pdo->prepare("
            SELECT p.name, c.name as category, SUM(oi.quantity) as sold
            FROM order_items oi
            JOIN products p ON oi.product_id = p.id
            LEFT JOIN categories c ON p.category_id = c.id
            JOIN orders o ON oi.order_id = o.id
            WHERE o.status != 'Cancelled'
            GROUP BY p.id, p.name, c.name
            ORDER BY sold DESC
            LIMIT 5
        ");
        $stmt->execute();
        $topProducts = $stmt->fetchAll(PDO::FETCH_ASSOC);

        return [
            'totalRevenue' => $totalRevenue,
            'totalOrders' => $totalOrders,
            'lowStockCount' => $lowStockCount,
            'newCustomers' => $newCustomers,
            'topProducts' => $topProducts
        ];
    } catch (PDOException $e) {
        error_log("Database Error in get_dashboard_kpis: " . $e->getMessage());
        // Return default values if database error
        return [
            'totalRevenue' => 0,
            'totalOrders' => 0,
            'lowStockCount' => 0,
            'newCustomers' => 0,
            'topProducts' => []
        ];
    }
}
}

/**
 * Generate slug from string
 */
if (!function_exists('generate_slug')) {
function generate_slug($string) {
    $slug = strtolower(trim(preg_replace('/[^A-Za-z0-9-]+/', '-', $string)));
    return $slug;
}
}
?>
