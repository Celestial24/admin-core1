<?php
/**
 * Database Installation Script
 * Run this file via browser to install the database and sample data
 * Example: http://localhost/core1admin/install_database.php
 */

// Include connection file
require_once 'connection.php';

header('Content-Type: text/html; charset=utf-8');
?>
<!DOCTYPE html>
<html>
<head>
    <title>Database Installation - iMARKET Admin Portal</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 900px;
            margin: 50px auto;
            padding: 20px;
            background: #f5f5f5;
        }
        .container {
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        h1 {
            color: #2c3c8c;
            border-bottom: 3px solid #4bc5ec;
            padding-bottom: 10px;
        }
        .step {
            background: #f9f9f9;
            padding: 15px;
            margin: 15px 0;
            border-left: 4px solid #4bc5ec;
            border-radius: 5px;
        }
        .success {
            color: #059669;
            background: #d1fae5;
            padding: 10px;
            border-radius: 5px;
            margin: 10px 0;
        }
        .error {
            color: #dc2626;
            background: #fee2e2;
            padding: 10px;
            border-radius: 5px;
            margin: 10px 0;
        }
        .info {
            color: #2563eb;
            background: #dbeafe;
            padding: 10px;
            border-radius: 5px;
            margin: 10px 0;
        }
        pre {
            background: #1f2937;
            color: #10b981;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
            font-size: 12px;
        }
        button {
            background: #2c3c8c;
            color: white;
            padding: 12px 24px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 16px;
            margin: 10px 5px 10px 0;
        }
        button:hover {
            background: #1e2a5f;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }
        th, td {
            padding: 10px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background: #2c3c8c;
            color: white;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🚀 iMARKET Admin Portal - Database Installation</h1>

        <?php
        $pdo = get_db_connection();
        $errors = [];
        $success = [];

        // Check if form was submitted
        if (isset($_POST['install'])) {
            echo '<div class="step">';
            echo '<h2>Installation Process Started...</h2>';

            try {
                // Read and execute database schema
                $schema_file = 'database_schema.sql';
                if (file_exists($schema_file)) {
                    $schema_sql = file_get_contents($schema_file);
                    // Split by semicolon and execute each statement
                    $statements = array_filter(array_map('trim', explode(';', $schema_sql)));
                    foreach ($statements as $statement) {
                        if (!empty($statement) && !preg_match('/^(SET|CREATE DATABASE|USE)/i', $statement)) {
                            try {
                                $pdo->exec($statement);
                            } catch (PDOException $e) {
                                // Ignore table already exists errors
                                if (strpos($e->getMessage(), 'already exists') === false) {
                                    $errors[] = "Schema: " . $e->getMessage();
                                }
                            }
                        }
                    }
                    $success[] = "Database schema executed successfully!";
                } else {
                    $errors[] = "Schema file not found: $schema_file";
                }

                // Read and execute sample data
                $data_file = 'sample_data.sql';
                if (file_exists($data_file)) {
                    $data_sql = file_get_contents($data_file);
                    // Remove comments and split by semicolon
                    $data_sql = preg_replace('/--.*$/m', '', $data_sql);
                    $statements = array_filter(array_map('trim', explode(';', $data_sql)));
                    
                    foreach ($statements as $statement) {
                        if (!empty($statement) && !preg_match('/^(SET|USE|SELECT|SHOW)/i', $statement)) {
                            try {
                                $pdo->exec($statement);
                            } catch (PDOException $e) {
                                // Ignore duplicate entry errors
                                if (strpos($e->getMessage(), 'Duplicate entry') === false) {
                                    $errors[] = "Data: " . $e->getMessage();
                                }
                            }
                        }
                    }
                    $success[] = "Sample data inserted successfully!";
                } else {
                    $errors[] = "Sample data file not found: $data_file";
                }

            } catch (Exception $e) {
                $errors[] = "Installation Error: " . $e->getMessage();
            }
            echo '</div>';
        }

        // Display errors and success messages
        foreach ($errors as $error) {
            echo '<div class="error">❌ ' . htmlspecialchars($error) . '</div>';
        }
        foreach ($success as $msg) {
            echo '<div class="success">✅ ' . htmlspecialchars($msg) . '</div>';
        }

        // Check database connection
        echo '<div class="step">';
        echo '<h2>📊 Database Connection Status</h2>';
        try {
            $pdo->getAttribute(PDO::ATTR_CONNECTION_STATUS);
            echo '<div class="success">✅ Database connection successful!</div>';
            echo '<div class="info">📝 Database: <strong>core1</strong><br>';
            echo '🔌 Host: <strong>localhost:' . (isset($port) ? $port : '3307') . '</strong><br>';
            echo '👤 User: <strong>' . (isset($username) ? $username : 'root') . '</strong></div>';
        } catch (Exception $e) {
            echo '<div class="error">❌ Database connection failed: ' . htmlspecialchars($e->getMessage()) . '</div>';
        }
        echo '</div>';

        // Check tables
        echo '<div class="step">';
        echo '<h2>📋 Database Tables Status</h2>';
        try {
            $tables = ['admin_users', 'categories', 'products', 'customers', 'customer_addresses', 
                      'orders', 'order_items', 'transactions', 'support_tickets', 'shipments'];
            $existing_tables = [];
            
            foreach ($tables as $table) {
                $stmt = $pdo->prepare("SHOW TABLES LIKE ?");
                $stmt->execute([$table]);
                if ($stmt->rowCount() > 0) {
                    $existing_tables[] = $table;
                    
                    // Count records
                    $count_stmt = $pdo->prepare("SELECT COUNT(*) as count FROM `$table`");
                    $count_stmt->execute();
                    $count = $count_stmt->fetch(PDO::FETCH_ASSOC)['count'];
                    
                    echo '<div class="info">✅ Table <strong>' . htmlspecialchars($table) . '</strong> exists with <strong>' . $count . '</strong> records</div>';
                } else {
                    echo '<div class="error">❌ Table <strong>' . htmlspecialchars($table) . '</strong> does not exist</div>';
                }
            }
            
            if (count($existing_tables) === count($tables)) {
                echo '<div class="success">✅ All tables are created and ready!</div>';
            } else {
                echo '<div class="error">⚠️ Some tables are missing. Please run the installation.</div>';
            }
        } catch (Exception $e) {
            echo '<div class="error">❌ Error checking tables: ' . htmlspecialchars($e->getMessage()) . '</div>';
        }
        echo '</div>';

        // Show sample data
        echo '<div class="step">';
        echo '<h2>📦 Sample Data Preview</h2>';
        try {
            // Check admin users
            $stmt = $pdo->query("SELECT COUNT(*) as count FROM admin_users");
            $admin_count = $stmt->fetch(PDO::FETCH_ASSOC)['count'];
            
            // Check products
            $stmt = $pdo->query("SELECT COUNT(*) as count FROM products");
            $product_count = $stmt->fetch(PDO::FETCH_ASSOC)['count'];
            
            // Check orders
            $stmt = $pdo->query("SELECT COUNT(*) as count FROM orders");
            $order_count = $stmt->fetch(PDO::FETCH_ASSOC)['count'];
            
            // Check customers
            $stmt = $pdo->query("SELECT COUNT(*) as count FROM customers");
            $customer_count = $stmt->fetch(PDO::FETCH_ASSOC)['count'];

            echo '<table>';
            echo '<tr><th>Table</th><th>Records</th><th>Status</th></tr>';
            echo '<tr><td>Admin Users</td><td>' . $admin_count . '</td><td>' . ($admin_count > 0 ? '✅' : '⚠️') . '</td></tr>';
            echo '<tr><td>Products</td><td>' . $product_count . '</td><td>' . ($product_count > 0 ? '✅' : '⚠️') . '</td></tr>';
            echo '<tr><td>Orders</td><td>' . $order_count . '</td><td>' . ($order_count > 0 ? '✅' : '⚠️') . '</td></tr>';
            echo '<tr><td>Customers</td><td>' . $customer_count . '</td><td>' . ($customer_count > 0 ? '✅' : '⚠️') . '</td></tr>';
            echo '</table>';

            if ($admin_count > 0) {
                echo '<div class="info">';
                echo '<strong>Default Admin Login:</strong><br>';
                $stmt = $pdo->query("SELECT username, email FROM admin_users LIMIT 1");
                $admin = $stmt->fetch(PDO::FETCH_ASSOC);
                echo 'Username: <strong>' . htmlspecialchars($admin['username']) . '</strong><br>';
                echo 'Email: <strong>' . htmlspecialchars($admin['email']) . '</strong><br>';
                echo 'Password: <strong>password</strong> (Please change after first login!)';
                echo '</div>';
            }

        } catch (Exception $e) {
            echo '<div class="error">❌ Error checking data: ' . htmlspecialchars($e->getMessage()) . '</div>';
        }
        echo '</div>';

        // Installation button
        if (!isset($_POST['install'])) {
            echo '<div class="step">';
            echo '<h2>🔧 Installation Options</h2>';
            echo '<form method="POST">';
            echo '<button type="submit" name="install">📦 Install Database & Sample Data</button>';
            echo '<p style="color: #666; margin-top: 10px;">Click this button to create all tables and insert sample data.</p>';
            echo '</form>';
            echo '</div>';
        } else {
            echo '<div class="step">';
            echo '<h2>✅ Installation Complete!</h2>';
            echo '<div class="success">';
            echo 'You can now <a href="index.php" style="color: #2c3c8c; font-weight: bold;">login to the admin portal</a>';
            echo '</div>';
            echo '</div>';
        }
        ?>

        <div class="step">
            <h2>📚 Manual Installation</h2>
            <p>If the automatic installation doesn't work, you can manually run the SQL files:</p>
            <ol>
                <li>Open phpMyAdmin: <a href="http://localhost/phpmyadmin" target="_blank">http://localhost/phpmyadmin</a></li>
                <li>Select or create the <strong>core1</strong> database</li>
                <li>Go to the SQL tab</li>
                <li>Copy and paste the contents of <strong>setup_database.sql</strong> or run <strong>database_schema.sql</strong> first, then <strong>sample_data.sql</strong></li>
                <li>Click "Go" to execute</li>
            </ol>
        </div>
    </div>
</body>
</html>















