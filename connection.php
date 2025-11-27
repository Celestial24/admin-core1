<?php
// =========================================================================
// core1admin/connection.php - Database Connection Configuration
// =========================================================================
// This file provides a centralized database connection for the entire application
// =========================================================================

// Database Connection Configuration
// *** UPDATE THESE WITH YOUR SERVER DETAILS ***
// *** DATABASE NAME: core1 ***
$host = getenv('DB_HOST') !== false ? getenv('DB_HOST') : 'localhost:3307';
$port = getenv('DB_PORT') !== false ? getenv('DB_PORT') : '3307';
$db_name = getenv('DB_NAME') !== false ? getenv('DB_NAME') : 'core1';      // Using the database name 'core1'
$username = getenv('DB_USERNAME') !== false ? getenv('DB_USERNAME') : 'root';      // REPLACE THIS if needed
$password = getenv('DB_PASSWORD') !== false ? getenv('DB_PASSWORD') : '';          // REPLACE THIS if needed

// Global PDO connection variable
$pdo = null;

/**
 * Internal helper to build a PDO connection instance.
 */
function create_pdo_connection($host, $port, $db_name, $username, $password) {
    return new PDO(
        "mysql:host=$host;port=$port;dbname=$db_name;charset=utf8mb4",
        $username,
        $password,
        [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false
        ]
    );
}

/**
 * Get database connection (Singleton pattern)
 * Returns a PDO connection object
 */
function get_db_connection() {
    global $pdo, $host, $port, $db_name, $username, $password;
    
    // If connection already exists, return it
    if ($pdo instanceof PDO) {
        return $pdo;
    }
    
    // Prepare candidate ports: configured port, optional fallback, and standard MySQL port
    $candidatePorts = array_unique(array_filter([
        $port,
        getenv('DB_FALLBACK_PORT') !== false ? getenv('DB_FALLBACK_PORT') : null,
        '3307',
    ]));

    $lastException = null;

    foreach ($candidatePorts as $candidatePort) {
        try {
            $pdo = create_pdo_connection($host, $candidatePort, $db_name, $username, $password);
            $GLOBALS['db_port_in_use'] = $candidatePort;
            $GLOBALS['pdo'] = $pdo;
            return $pdo;
        } catch (PDOException $e) {
            $lastException = $e;
            error_log("Database Connection Error ({$host}:{$candidatePort}): " . $e->getMessage());
        }
    }

    $friendlyMessage = "Database Connection Error: Unable to connect to the MySQL server using the supplied credentials.";
    if ($lastException instanceof PDOException) {
        $friendlyMessage .= " Last error: " . $lastException->getMessage();
    }

    throw new RuntimeException($friendlyMessage, 0, $lastException);
}

?>
