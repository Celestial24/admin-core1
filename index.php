<?php
// =========================================================================
// iMARKET ADMIN PORTAL - Main Application File
//
// NOTE: This file is a monolithic structure combining connection, functions,
// and presentation for simplicity in a single-file environment.
// =========================================================================

// =========================================================================
// 1. DATABASE CONNECTION CONFIGURATION
// =========================================================================
// Include the centralized database connection file
require_once 'connection.php';

// Get the database connection
try {
    $pdo = get_db_connection();
} catch (RuntimeException $e) {
    http_response_code(500);
    $safeMessage = htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8');
    $supportTips = [
        'Ensure that the MySQL server is running.',
        'Double-check the credentials in connection.php or your environment variables.',
        'Confirm that the correct port is open (defaults attempted: ' . htmlspecialchars(implode(', ', array_unique(array_filter([
            getenv('DB_PORT') !== false ? getenv('DB_PORT') : '3307',
            getenv('DB_FALLBACK_PORT') !== false ? getenv('DB_FALLBACK_PORT') : null,
            '3306',
        ]))), ENT_QUOTES, 'UTF-8') . ').',
    ];
    echo "<!DOCTYPE html>
<html lang=\"en\">
<head>
    <meta charset=\"UTF-8\">
    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">
    <title>System Configuration Error</title>
    <style>
        body { font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #0f172a; color: #e2e8f0; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; }
        .error-card { background: #111827; padding: 2.5rem; border-radius: 1rem; max-width: 520px; box-shadow: 0 25px 50px -12px rgba(30, 64, 175, 0.45); border: 1px solid rgba(59, 130, 246, 0.2); }
        h1 { font-size: 1.75rem; margin-top: 0; margin-bottom: 1rem; color: #93c5fd; }
        p { line-height: 1.6; margin-bottom: 1rem; }
        ul { padding-left: 1.25rem; margin-bottom: 1.5rem; }
        li { margin-bottom: 0.5rem; }
        code { background: rgba(59, 130, 246, 0.15); padding: 0.2rem 0.4rem; border-radius: 0.35rem; color: #bfdbfe; }
        .details { margin-top: 1.5rem; padding: 1rem; border-radius: 0.75rem; background: rgba(148, 163, 184, 0.1); border: 1px solid rgba(148, 163, 184, 0.2); color: #cbd5f5; font-size: 0.9rem; word-break: break-word; }
    </style>
</head>
<body>
    <div class=\"error-card\">
        <h1>Database Connection Required</h1>
        <p>We couldn’t reach the database server, so the admin portal is temporarily unavailable. Please review the configuration below and try again.</p>
        <ul>";
    foreach ($supportTips as $tip) {
        echo '<li>' . htmlspecialchars($tip, ENT_QUOTES, 'UTF-8') . '</li>';
    }
    echo "</ul>
        <div class=\"details\"><strong>Last error message</strong><br>{$safeMessage}</div>
    </div>
</body>
</html>";
    exit();
}


// =========================================================================
// 2. SESSION AND FUNCTION DEFINITIONS
// =========================================================================

// Start session if not already started
if (session_status() == PHP_SESSION_NONE) {
    session_start();
}

// ===========================================
// MODULE 0: AUTHENTICATION & OTP 
// ===========================================

/**
 * Fetches admin user data by username. Uses prepared statements.
 */
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

/**
 * Fetches admin user profile details by ID, including phone_number.
 */
function get_admin_user_details($pdo, $id) {
    try {
        $stmt = $pdo->prepare("SELECT id, username, role, full_name, email, phone_number, password_hash, otp_code, otp_expiry, created_at, updated_at FROM admin_users WHERE id = ?");
        $stmt->execute([$id]);
        return $stmt->fetch(PDO::FETCH_ASSOC);
    } catch (PDOException $e) {
        error_log("Database Error in get_admin_user_details: " . $e->getMessage());
        return false;
    }
}

/**
 * Generates a 6-digit cryptographically secure OTP.
 */
function generate_otp() {
    return strval(random_int(100000, 999999));
}

/**
 * Saves the OTP and expiry time (5 minutes) to the database.
 */
function save_otp($pdo, $user_id, $otp) {
    // Ensure OTP is a clean string (6 digits)
    $otp = trim(strval($otp));
    if (strlen($otp) !== 6 || !ctype_digit($otp)) {
        error_log("Invalid OTP format: '{$otp}' (length: " . strlen($otp) . ")");
        return false;
    }
    
    $expiry = date('Y-m-d H:i:s', time() + 300); // 300 seconds (5 minutes)
    try {
        // [SECURITY: USING PREPARED STATEMENT]
        $stmt = $pdo->prepare("UPDATE admin_users SET otp_code = ?, otp_expiry = ? WHERE id = ?");
        $result = $stmt->execute([$otp, $expiry, $user_id]);
        
        if ($result) {
            error_log("OTP saved successfully for user_id: {$user_id}, OTP: {$otp}, Expiry: {$expiry}");
        } else {
            error_log("Failed to save OTP for user_id: {$user_id}");
        }
        
        return $result;
    } catch (PDOException $e) {
        error_log("Database Error in save_otp: " . $e->getMessage());
        return false;
    }
}

/**
 * Simulates sending the OTP via Email to the provided email address.
 */
function simulate_send_otp($email, $otp) {
    // Manually load PHPMailer if not already loaded
    if (!class_exists('PHPMailer\\PHPMailer\\PHPMailer')) {
        $phpmailer_path = __DIR__ . '/PHPMailer/src/PHPMailer.php';
        if (file_exists($phpmailer_path)) {
            require_once $phpmailer_path;
            require_once __DIR__ . '/PHPMailer/src/SMTP.php';
            require_once __DIR__ . '/PHPMailer/src/Exception.php';
            error_log("PHPMailer loaded manually in simulate_send_otp from: {$phpmailer_path}");
        } else {
            error_log("PHPMailer class not found and files not available at: {$phpmailer_path}");
            return "An OTP code has been generated and sent to your email. Please check your inbox and spam folder.";
        }
    }

    // PHPMailer is available — attempt real send via Gmail
    try {
        $mail = new PHPMailer\PHPMailer\PHPMailer(true);

        // Enable verbose debug output (set to 0 for production, 2 for detailed debug)
        $mail->SMTPDebug = 0;
        $mail->Debugoutput = function($str, $level) {
            error_log("PHPMailer Debug (level {$level}): {$str}");
        };

        // Gmail SMTP configuration
        $smtpHost = getenv('SMTP_HOST') ?: (defined('SMTP_HOST') ? SMTP_HOST : 'smtp.gmail.com');
        $smtpPort = getenv('SMTP_PORT') ?: (defined('SMTP_PORT') ? SMTP_PORT : 587);
        $smtpUser = getenv('SMTP_USER') ?: (defined('SMTP_USER') ? SMTP_USER : 'linbilcelestre31@gmail.com');
        $smtpPass = getenv('SMTP_PASS') ?: (defined('SMTP_PASS') ? SMTP_PASS : 'uutf yynp cvjz rpwp');
        $smtpFrom = getenv('SMTP_FROM') ?: (defined('SMTP_FROM') ? SMTP_FROM : $smtpUser);
        $smtpFromName = getenv('SMTP_FROM_NAME') ?: (defined('SMTP_FROM_NAME') ? SMTP_FROM_NAME : 'iMARKET');

        // Server settings for Gmail
        $mail->isSMTP();
        $mail->Host = $smtpHost;
        $mail->SMTPAuth = true;
        $mail->Username = $smtpUser;
        $mail->Password = $smtpPass;
        $mail->SMTPSecure = PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_STARTTLS;
        $mail->Port = intval($smtpPort);
        $mail->CharSet = 'UTF-8';

        // Additional Gmail-specific settings to handle SSL
        $mail->SMTPOptions = array(
            'ssl' => array(
                'verify_peer' => false,
                'verify_peer_name' => false,
                'allow_self_signed' => true
            )
        );

        // Recipients
        $mail->setFrom($smtpFrom, $smtpFromName);
        $mail->addAddress($email);

        // Content
        $mail->isHTML(true);
        $mail->Subject = 'Verify your email - iMARKET';
        $mail->Body = "
<!DOCTYPE html>
<html lang=\"en\">
<head>
    <meta charset=\"UTF-8\">
    <style>
        body { font-family: Arial, sans-serif; background: #f5f5f5; }
        .container { max-width: 600px; margin: 20px auto; background: white; padding: 30px; border-radius: 8px; }
        .header { background: linear-gradient(135deg, #1e40af 0%, #3b82f6 100%); color: white; padding: 20px; text-align: center; border-radius: 8px; }
        .content { margin: 20px 0; color: #333; }
        .otp-box { background: #1e40af; color: white; font-size: 32px; font-weight: bold; text-align: center; padding: 20px; border-radius: 8px; letter-spacing: 4px; margin: 20px 0; }
        .footer { text-align: center; color: #666; font-size: 12px; margin-top: 20px; border-top: 1px solid #ddd; padding-top: 20px; }
    </style>
</head>
<body>
    <div class=\"container\">
        <div class=\"header\">
            <h1>iMARKET</h1>
            <p>Email Verification</p>
        </div>
        <div class=\"content\">
            <p>Hello,</p>
            <p>Use the verification code below to activate your account. This code expires in 5 minutes.</p>
            <div class=\"otp-box\">{$otp}</div>
            <p>If you didn't request this code, please ignore this email.</p>
            <p>Never share this code with anyone.</p>
        </div>
        <div class=\"footer\">
            <p>© 2024 iMARKET Admin Portal. All rights reserved.</p>
        </div>
    </div>
</body>
</html>
        ";
        $mail->AltBody = "Your OTP code: {$otp}\n\nThis code expires in 5 minutes.\n\nIf you didn't request this, ignore this email.\n\n— iMARKET Admin Portal";

        // Send email
        $result = $mail->send();
        if ($result) {
            error_log("✓ OTP sent successfully to {$email} via Gmail SMTP");
            return "An OTP code has been sent to your email address ({$email}). Please check your inbox and spam folder.";
        } else {
            error_log("✗ PHPMailer send failed: " . $mail->ErrorInfo);
            return "An OTP code has been generated but there was an issue sending the email. Please contact the administrator. Error: " . $mail->ErrorInfo;
        }
    } catch (PHPMailer\PHPMailer\Exception $e) {
        error_log("✗ PHPMailer Exception: " . $e->getMessage());
        if (isset($mail)) {
            error_log("✗ PHPMailer ErrorInfo: " . $mail->ErrorInfo);
        }
        return "An OTP code has been generated but there was an issue sending the email. Please contact the administrator. Error: " . $e->getMessage();
    } catch (Exception $e) {
        error_log("✗ General Exception in simulate_send_otp: " . $e->getMessage());
        return "An OTP code has been generated but there was an issue sending the email. Please contact the administrator.";
    }
}

/**
 * PHASE 1: Authenticates the user and initiates OTP via Email.
 */
function authenticate_admin($pdo, $username, $password) {
    $user = get_admin_user_by_username($pdo, $username);

    if ($user && password_verify($password, $user['password_hash'])) {
        // Ensure email exists before sending OTP
        if (empty($user['email'])) {
            return ['success' => false, 'message' => "Login failed: No registered email address for OTP."];
        }

        $otp = generate_otp();
        $recipient = $user['email']; // Using email for OTP
        
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
            // This error typically happens due to missing DB columns
            return ['success' => false, 'message' => "Login failed: Could not save OTP. Please check database permissions and column names."];
        }
    } else {
        return ['success' => false, 'message' => "Login failed: Incorrect username or password."];
    }
}

/**
 * PHASE 2: Verifies the entered OTP and completes login.
 */
function verify_otp_and_login($pdo, $user_id, $otp_input) {
    // Normalize the OTP input - remove any non-numeric characters and ensure it's a string
    $otp_input = preg_replace('/[^0-9]/', '', trim(strval($otp_input)));
    
    // Validate input length
    if (empty($otp_input) || strlen($otp_input) !== 6) {
        error_log("OTP verification failed: Invalid input length. Input: '{$otp_input}', Length: " . strlen($otp_input));
        return "Error: OTP code must be exactly 6 digits.";
    }
    
    // Ensure user_id is valid
    $user_id = intval($user_id);
    if ($user_id <= 0) {
        error_log("OTP verification failed: Invalid user_id: {$user_id}");
        return "Error: Invalid user session. Please log in again.";
    }
    
    // Get user data from database
    $user = get_admin_user_details($pdo, $user_id);
    
    if (!$user) {
        error_log("OTP verification failed: User not found for user_id: {$user_id}");
        return "Error: User data not found during OTP check. Please log in again.";
    }

    // Check if OTP exists in database
    if (empty($user['otp_code'])) {
        error_log("OTP verification failed: No OTP code found for user_id: {$user_id}");
        return "Error: OTP expired or not generated. Please log in again to generate a new code.";
    }

    // Normalize the stored OTP code - ensure it's a clean 6-digit string
    $stored_otp = preg_replace('/[^0-9]/', '', trim(strval($user['otp_code'])));
    
    // Ensure stored OTP is exactly 6 digits (should always be, but safety check)
    if (strlen($stored_otp) !== 6) {
        error_log("OTP verification failed: Stored OTP has invalid length. Stored: '{$stored_otp}', Length: " . strlen($stored_otp));
        return "Error: Invalid OTP in database. Please log in again to generate a new code.";
    }
    
    // Ensure input is exactly 6 digits (already validated above, but double-check)
    if (strlen($otp_input) !== 6) {
        error_log("OTP verification failed: Input OTP has invalid length after normalization. Input: '{$otp_input}', Length: " . strlen($otp_input));
        return "Error: Invalid OTP format. Please enter exactly 6 digits.";
    }

    // Check if OTP has expired FIRST (before comparing)
    if (!empty($user['otp_expiry'])) {
        try {
            $current_time = new DateTime();
            $expiry_time = new DateTime($user['otp_expiry']);
            
    if ($current_time > $expiry_time) {
                // Clear expired OTP
                try {
                    $stmt = $pdo->prepare("UPDATE admin_users SET otp_code = NULL, otp_expiry = NULL WHERE id = ?");
                    $stmt->execute([$user_id]);
                    error_log("OTP expired for user_id: {$user_id}");
                } catch (PDOException $e) {
                    error_log("Error clearing expired OTP: " . $e->getMessage());
                }
        return "OTP expired. Please log in again to generate a new code.";
            }
        } catch (Exception $e) {
            error_log("Error parsing OTP expiry time: " . $e->getMessage());
            return "Error: Invalid OTP expiry time. Please log in again.";
        }
    } else {
        error_log("OTP verification failed: No expiry time set for user_id: {$user_id}");
        return "Error: OTP expiry time not set. Please log in again.";
    }

    // Compare OTP codes (both normalized as 6-digit strings)
    if ($stored_otp !== $otp_input) {
        error_log("OTP mismatch for user_id {$user_id} - Stored: '{$stored_otp}' (length: " . strlen($stored_otp) . "), Input: '{$otp_input}' (length: " . strlen($otp_input) . ")");
        return "Invalid OTP code. Please check and try again.";
    }

    // OTP is valid! Clear the OTP fields and log in.
    try {
        $stmt = $pdo->prepare("UPDATE admin_users SET otp_code = NULL, otp_expiry = NULL WHERE id = ?");
        $stmt->execute([$user_id]);
        error_log("OTP verified successfully for user_id: {$user_id}, username: {$user['username']}");
    } catch (PDOException $e) {
        error_log("Error clearing OTP after successful verification: " . $e->getMessage());
        // Continue with login even if clearing fails
    }
    
    // Set session variables
    $_SESSION['admin_logged_in'] = true;
    $_SESSION['admin_id'] = $user['id'];
    $_SESSION['admin_username'] = $user['username'];
    $_SESSION['admin_role'] = $user['role'];
    
    // Clear temporary session variables
    unset($_SESSION['admin_awaiting_otp']);
    unset($_SESSION['temp_admin_id']);
    unset($_SESSION['temp_admin_username']);
    
    return "Successful login! Welcome, " . htmlspecialchars($user['username']) . ".";
}


/**
 * Creates a new admin user account.
 */
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

/**
 * Function to handle redirect back to Login/Register from OTP screen.
 */
function handle_login_redirect() {
    // Clear temporary session data
    unset($_SESSION['admin_awaiting_otp']);
    unset($_SESSION['temp_admin_id']);
    unset($_SESSION['temp_admin_username']);
    
    // Redirect to main page (login view)
    header("Location: " . basename(__FILE__) . "?msg=" . urlencode("Your session has been cleared. Log in again to generate a new OTP."));
    exit();
}

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

/**
 * Handles profile updates, including phone_number.
 */
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

// ===========================================
// MODULE 2: ORDERS MANAGEMENT FUNCTIONS (FROM functions.php)
// ===========================================

/**
 * Update order status
 */
function update_order_status($order_id, $new_status, $pdo = null) {
    if ($pdo === null) {
        // Try to get PDO if not passed
        global $pdo;
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


// ===========================================
// FORM HANDLER (Handles all POST requests)
// ===========================================

function handle_form_submission($pdo, $action, $post_data) {
    $result_message = "";
    $redirect_base = basename(__FILE__);

    switch ($action) {
        // --- LOGIN ACTION (STEP 1: USERname/PASSWORD) ---
        case 'login':
            $auth_result = authenticate_admin($pdo, $post_data['username'], $post_data['password']);
            
            if ($auth_result['success'] && $auth_result['redirect_view'] === 'otp') {
                header("Location: " . $redirect_base . "?view=otp&msg=" . urlencode($auth_result['message']));
            } else {
                header("Location: " . $redirect_base . "?msg=" . urlencode($auth_result['message']));
            }
            exit();

        // --- OTP VERIFICATION ACTION (STEP 2: OTP) ---
        case 'otp_verify':
            // Get OTP from POST data and normalize it
            $otp_input = isset($post_data['otp_code']) ? trim(strval($post_data['otp_code'])) : '';
            
            // Get user_id from session (primary) or from POST (fallback)
            $user_id = isset($_SESSION['temp_admin_id']) ? intval($_SESSION['temp_admin_id']) : (isset($post_data['user_id']) ? intval($post_data['user_id']) : null);
            
            // Validate OTP input
            if (empty($otp_input)) {
                $result_message = "Error: Please enter the OTP code.";
                header("Location: " . $redirect_base . "?view=otp&msg=" . urlencode($result_message));
                exit();
            }
            
            // Remove any non-numeric characters and ensure it's exactly 6 digits
            $otp_input = preg_replace('/[^0-9]/', '', $otp_input);
            
            if (strlen($otp_input) !== 6) {
                $result_message = "Error: OTP code must be exactly 6 digits. You entered: " . strlen($otp_input) . " digit(s).";
                header("Location: " . $redirect_base . "?view=otp&msg=" . urlencode($result_message));
                exit();
            }
            
            // Validate user_id
            if (!$user_id || $user_id <= 0) {
                $result_message = "Session error. Please log in again to generate a new OTP.";
                // Clear session and redirect to login
                unset($_SESSION['admin_awaiting_otp']);
                unset($_SESSION['temp_admin_id']);
                unset($_SESSION['temp_admin_username']);
                header("Location: " . $redirect_base . "?msg=" . urlencode($result_message));
                exit();
            }

            // Verify OTP and login
            $verification_result = verify_otp_and_login($pdo, $user_id, $otp_input);
            
            // Check if login was successful
            if (stripos($verification_result, 'successful') !== false || stripos($verification_result, 'welcome') !== false) {
                // Successful login - redirect to dashboard
                header("Location: " . $redirect_base . "?msg=" . urlencode($verification_result));
            } else {
                // Failed verification - stay on OTP page with error message
                header("Location: " . $redirect_base . "?view=otp&msg=" . urlencode($verification_result));
            }
            exit();

        // --- REGISTER ACTION (IMPROVED: Initiates OTP flow immediately) ---
        case 'register':
            // Added full_name validation
            if (empty($post_data['username']) || empty($post_data['password']) || empty($post_data['email']) || empty($post_data['full_name']) || $post_data['password'] !== $post_data['confirm_password']) {
                $result_message = "Registration failed: Username, Password, Email, Full Name are required, and passwords must match.";
                header("Location: " . $redirect_base . "?view=register&msg=" . urlencode($result_message));
                exit();
            }

            $reg_result = create_admin_account(
                $pdo, 
                $post_data['username'], 
                $post_data['password'], 
                $post_data['email'], 
                $post_data['phone_number'] ?? '', // Phone number is optional
                $post_data['full_name']
            );
            
            if ($reg_result['success']) {
                // SUCCESS: Initiate OTP flow immediately for the newly created user
                $otp = generate_otp();
                // USING EMAIL FOR OTP
                if (save_otp($pdo, $reg_result['user_id'], $otp)) {
                    $otp_message = simulate_send_otp($reg_result['email'], $otp);

                    // Set temporary session for OTP validation
                    $_SESSION['admin_awaiting_otp'] = true;
                    $_SESSION['temp_admin_id'] = $reg_result['user_id'];
                    $_SESSION['temp_admin_username'] = $reg_result['username'];
                    
                    // Redirect to OTP verification page
                    header("Location: " . $redirect_base . "?view=otp&msg=" . urlencode($otp_message));
                } else {
                    // Fail OTP save, redirect to login with error
                    header("Location: " . $redirect_base . "?msg=" . urlencode("Registration successful, but failed to start OTP. Please login manually."));
                }
            } else {
                // Registration failed due to validation or database error
                header("Location: " . $redirect_base . "?view=register&msg=" . urlencode($reg_result['message']));
            }
            exit();
            
        // --- ADMIN PROFILE UPDATE LOGIC ---
        case 'update_profile':
            $admin_id = $_SESSION['admin_id'] ?? null;
            if (!$admin_id) {
                 header("Location: " . $redirect_base . "?msg=" . urlencode("Authentication required to update profile."));
                 exit();
            }
            
            $result_message = update_admin_profile(
                $pdo, 
                $admin_id, 
                $post_data['new_username'] ?? '',
                $post_data['full_name'] ?? '',
                $post_data['email'] ?? '',
                $post_data['phone_number'] ?? '', // Phone number is optional in profile update
                $post_data['current_password'] ?? '',
                $post_data['new_password'] ?? ''
            );
            
            header("Location: " . $redirect_base . "?module=user&submodule=profile&msg=" . urlencode($result_message));
            exit();
            
        // --- PRODUCT CRUD ACTIONS ---
        case 'add_product':
            require_once 'functions.php';
            $name = $post_data['name'] ?? '';
            $slug = generate_slug($name);
            $description = $post_data['description'] ?? '';
            $price = floatval($post_data['price'] ?? 0);
            $stock = intval($post_data['stock'] ?? 0);
            $category_id = intval($post_data['category_id'] ?? 0);
            $status = $post_data['status'] ?? 'Active';
            $image_url = $post_data['image_url'] ?? null;
            
            $result = add_product($pdo, $name, $slug, $description, $price, $stock, $category_id, $status, $image_url);
            $result_message = $result['message'];
            break;
            
        case 'edit_product':
            require_once 'functions.php';
            $id = intval($post_data['id'] ?? 0);
            $name = $post_data['name'] ?? '';
            $slug = generate_slug($name);
            $description = $post_data['description'] ?? '';
            $price = floatval($post_data['price'] ?? 0);
            $stock = intval($post_data['stock'] ?? 0);
            $category_id = intval($post_data['category_id'] ?? 0);
            $status = $post_data['status'] ?? 'Active';
            $image_url = $post_data['image_url'] ?? null;
            
            $result = update_product($pdo, $id, $name, $slug, $description, $price, $stock, $category_id, $status, $image_url);
            $result_message = $result['message'];
            break;
            
        case 'delete_product':
            require_once 'functions.php';
            $id = intval($post_data['id'] ?? 0);
            $result = delete_product($pdo, $id);
            $result_message = $result['message'];
            break;
            
        case 'clear_all_products':
            require_once 'functions.php';
            try {
                $stmt = $pdo->prepare("DELETE FROM products");
                $stmt->execute();
                $deleted_count = $stmt->rowCount();
                $result_message = "Successfully deleted {$deleted_count} product(s) from database.";
                $module = 'product';
                $submodule = 'products';
            } catch (PDOException $e) {
                error_log("Error clearing products: " . $e->getMessage());
                $result_message = "Error clearing products: " . $e->getMessage();
                $module = 'product';
                $submodule = 'products';
            }
            break;
            
        // --- CATEGORY CRUD ACTIONS ---
        case 'add_category':
            require_once 'functions.php';
            $name = $post_data['name'] ?? '';
            $slug = generate_slug($name);
            $description = $post_data['description'] ?? '';
            $status = $post_data['status'] ?? 'Active';
            
            $result = add_category($pdo, $name, $slug, $description, $status);
            $result_message = $result['message'];
            $submodule = 'categories';
            break;
            
        case 'edit_category':
            require_once 'functions.php';
            $id = intval($post_data['id'] ?? 0);
            $name = $post_data['name'] ?? '';
            $slug = generate_slug($name);
            $description = $post_data['description'] ?? '';
            $status = $post_data['status'] ?? 'Active';
            
            $result = update_category($pdo, $id, $name, $slug, $description, $status);
            $result_message = $result['message'];
            $submodule = 'categories';
            break;
            
        case 'delete_category':
            require_once 'functions.php';
            $id = intval($post_data['id'] ?? 0);
            $result = delete_category($pdo, $id);
            $result_message = $result['message'];
            $submodule = 'categories';
            break;
            
        // --- SUPPORT TICKET ACTIONS ---
        case 'update_ticket':
            require_once 'functions.php';
            $id = intval($post_data['id'] ?? 0);
            $status = $post_data['status'] ?? 'Open';
            $priority = $post_data['priority'] ?? null;
            $assigned_to = !empty($post_data['assigned_to']) ? intval($post_data['assigned_to']) : null;
            
            $result = update_support_ticket($pdo, $id, $status, $priority, $assigned_to);
            $result_message = $result['message'];
            $module = 'support';
            break;
            
        // --- ADMIN USER ACTIONS ---
        case 'delete_admin':
            require_once 'functions.php';
            $id = intval($post_data['id'] ?? 0);
            $result = delete_admin_user($pdo, $id);
            $result_message = $result['message'];
            $module = 'user';
            $submodule = 'admins';
            break;
            
        case 'update_order_status':
            $order_id = $post_data['id'] ?? null;
            $new_status = $post_data['status'] ?? null;
            
            if ($order_id && $new_status) {
                if (update_order_status($order_id, $new_status, $pdo)) {
                    $result_message = "Order #$order_id status successfully updated to **$new_status**.";
                } else {
                    $result_message = "Failed to update order status. Please check database configuration.";
                }
            } else {
                $result_message = "Error: Missing order ID or status.";
            }
            break;
            
        default:
            $result_message = "Error: Unknown action requested.";
            break;
    }

    // Default redirect for non-auth actions
    $module = $post_data['module'] ?? 'dashboard';
    $submodule = $post_data['submodule'] ?? '';
    header("Location: " . $redirect_base . "?module=$module&submodule=$submodule&msg=" . urlencode($result_message));
    exit();
}

// =========================================================================
// 3. TOP-LEVEL REQUEST HANDLER (Handles POST and GET actions)
// =========================================================================

// NEW ACTION: Handles request to return to login/clear session
if (isset($_GET['action']) && $_GET['action'] === 'return_to_login') {
    handle_login_redirect();
}

// Handle LOGOUT request
if (isset($_GET['action']) && $_GET['action'] === 'logout') {
    handle_logout();
}

// Include functions.php here to ensure all database-dependent functions are available
// Functions.php checks for existing functions to avoid redeclaration.
require_once 'functions.php';

// Handle POST request
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
    // Re-check for required functions just in case the include failed earlier
    if (!function_exists('update_order_status')) {
        error_log("FATAL: Required functions were not loaded.");
        // Fallback to minimal response
        header("Location: " . basename(__FILE__) . "?msg=" . urlencode("FATAL: System functions failed to load."));
        exit();
    }
    handle_form_submission($pdo, $_POST['action'], $_POST);
}

// Check login status
$is_logged_in = isset($_SESSION['admin_logged_in']) && $_SESSION['admin_logged_in'] === true;
$is_awaiting_otp = isset($_SESSION['admin_awaiting_otp']) && $_SESSION['admin_awaiting_otp'] === true;

$message = $_GET['msg'] ?? '';
$view = $_GET['view'] ?? '';

$is_register_page = $view === 'register';
$is_otp_page = $view === 'otp';

// State management to ensure correct view is shown
if ($is_logged_in) {
    $is_register_page = false;
    $is_otp_page = false;
} else if ($is_awaiting_otp) {
    $is_otp_page = true;
    $is_register_page = false;
} else if ($is_otp_page && !$is_awaiting_otp) {
    header("Location: " . basename(__FILE__) . "?msg=" . urlencode("Please log in first."));
    exit();
}

// Fetch display details
$admin_username = htmlspecialchars($_SESSION['admin_username'] ?? ($is_awaiting_otp ? $_SESSION['temp_admin_username'] : 'Admin'));
$admin_role = htmlspecialchars($_SESSION['admin_role'] ?? 'User');

// Fetch admin details for the profile page if logged in
$admin_details = [];
if ($is_logged_in && isset($_SESSION['admin_id'])) {
    $admin_details = get_admin_user_details($pdo, $_SESSION['admin_id']);
}

// Fetch data from database for display
if ($is_logged_in) {
    try {
        // Fetch data from database
        $mock_products = get_products_list($pdo);
        $mock_orders = get_orders_list($pdo);
        $kpi_data = get_dashboard_kpis($pdo);
        $mock_categories = get_categories_list($pdo);
        $mock_transactions = get_transactions_list($pdo);
        $mock_shipments = get_shipments_list($pdo);
        $mock_customers = get_customers_list($pdo);
        $mock_support_tickets = get_support_tickets_list($pdo);
        $mock_admin_users = get_admin_users_list($pdo);
        
        // Fetch addresses for the Shipping Module
        $mockAddresses = get_customer_addresses($pdo);

    } catch (Exception $e) {
        error_log("Error fetching dashboard data: " . $e->getMessage());
        $mock_products = [];
        $mock_orders = [];
        $mockAddresses = [];
        $mock_categories = [];
        $mock_transactions = [];
        $mock_shipments = [];
        $mock_customers = [];
        $mock_support_tickets = [];
        $mock_admin_users = [];
        $kpi_data = [
            'totalRevenue' => 0,
            'totalOrders' => 0,
            'lowStockCount' => 0,
            'newCustomers' => 0,
            'topProducts' => []
        ];
    }
} else {
    $mock_products = [];
    $mock_orders = [];
    $mockAddresses = [];
    $mock_categories = [];
    $mock_transactions = [];
    $mock_shipments = [];
    $mock_customers = [];
    $mock_support_tickets = [];
    $mock_admin_users = [];
    $kpi_data = [];
}


// =========================================================================
// 4. CONDITIONAL HTML RENDERING (LOGIN/REGISTER/OTP PAGE or ADMIN DASHBOARD)
// =========================================================================
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php 
        if ($is_logged_in) {
            echo 'iMARKET Admin Portal';
        } else if ($is_otp_page) {
            echo 'OTP Verification | iMARKET'; 
        } else if ($is_register_page) {
            echo 'Admin Registration | iMARKET';
        } else {
            echo 'Admin Login | iMARKET';
        }
    ?></title>
    <!-- Lucide Icons CDN -->
    <script src="https://unpkg.com/lucide@latest/dist/umd/lucide.js"></script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@100..900&display=swap" rel="stylesheet">
    <style>
        /* --- 1. Custom Variables & Base Styles --- */
        :root {
            --color-primary-dark: #1e40af;
            --color-primary: #3b82f6;
            --color-accent-cyan: #06b6d4;
            --color-dark-grey: #1e293b;
            --color-light-grey: #cbd5e1;
            --color-background: #f8fafc;
            --color-white: #ffffff;
            --color-gray-500: #64748b;
            --color-gray-400: #94a3b8;
            --color-gray-300: #cbd5e1;
            --color-gray-200: #e2e8f0;
            --color-gray-100: #f1f5f9;
            --color-indigo-600: #4f46e5;
            --color-indigo-500: #6366f1;
            --color-red-600: #dc2626;
            --color-red-500: #ef4444;
            --color-green-600: #059669;
            --color-green-500: #10b981;
            --color-yellow-600: #d97706;
            --color-yellow-500: #f59e0b;
            --color-blue-600: #2563eb;
            --color-purple-600: #9333ea;
            --shadow-sm: 0 1px 2px 0 rgba(0, 0, 0, 0.05);
            --shadow-md: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -2px rgba(0, 0, 0, 0.1);
            --shadow-lg: 0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -4px rgba(0, 0, 0, 0.1);
            --shadow-xl: 0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04);
            --gradient-primary: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            --gradient-success: linear-gradient(135deg, #84fab0 0%, #8fd3f4 100%);
            --gradient-warning: linear-gradient(135deg, #fbc2eb 0%, #a6c1ee 100%);
            --gradient-danger: linear-gradient(135deg, #fa709a 0%, #fee140 100%);
        }

        * {
            box-sizing: border-box;
        }

        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: linear-gradient(135deg, #f8fafc 0%, #e2e8f0 100%);
            margin: 0;
            padding: 0;
            color: #0f172a;
            line-height: 1.6;
            -webkit-font-smoothing: antialiased;
            -moz-osx-font-smoothing: grayscale;
        }
        
        /* Base Button Style */
        .btn-base {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            border: none;
            cursor: pointer;
            border-radius: 0.5rem;
            font-weight: 600;
            transition: all 0.2s;
            white-space: nowrap; /* Prevent buttons from wrapping awkwardly */
        }
        .btn-primary { 
            background: linear-gradient(135deg, var(--color-primary-dark) 0%, var(--color-indigo-600) 100%);
            color: var(--color-white); 
            padding: 0.75rem 1.5rem; 
            font-size: 0.9375rem;
            font-weight: 600;
            box-shadow: 0 4px 12px rgba(30, 64, 175, 0.3);
        }
        .btn-primary:hover { 
            background: linear-gradient(135deg, #1e3a8a 0%, #4338ca 100%);
            transform: translateY(-2px); 
            box-shadow: 0 6px 20px rgba(30, 64, 175, 0.4); 
        }
        .btn-primary:active {
            transform: translateY(0);
            box-shadow: 0 2px 8px rgba(30, 64, 175, 0.3);
        }
        .btn-secondary {
            background-color: #e5e7eb;
            color: #374151;
            padding: 0.75rem 1.5rem;
            font-size: 0.9375rem;
            font-weight: 600;
        }
        .btn-secondary:hover {
            background-color: #d1d5db;
            transform: translateY(-1px);
            box-shadow: var(--shadow-sm);
        }
        .btn-secondary:active {
            transform: translateY(0);
        }
        .w-full {
            width: 100%;
        }

        /* --- Custom Modal Styles (for replacing alert/confirm) --- */
        .modal-backdrop {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0, 0, 0, 0.6);
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 50;
        }
        .modal-content {
            background-color: var(--color-white);
            padding: 2rem;
            border-radius: 0.75rem;
            max-width: 450px;
            width: 90%;
            box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04);
        }

        /* --- Login/Register/OTP Specific Styles --- */
        <?php if (!$is_logged_in): ?>
        body {
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
        }
        .login-container {
            width: 100%;
            max-width: 420px;
            padding: 2.5rem;
            background: linear-gradient(135deg, var(--color-white) 0%, #f8fafc 100%);
            border-radius: 1.5rem;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.15);
            border: 1px solid rgba(226, 232, 240, 0.8);
            backdrop-filter: blur(10px);
        }
        .login-container .header { text-align: center; margin-bottom: 2rem; }
        .login-container .logo-text { color: var(--color-dark-grey); font-weight: 900; letter-spacing: 0.1em; font-size: 1.5rem; display: block; }
        .login-container .logo-icon { color: var(--color-accent-cyan); width: 2.5rem; height: 2.5rem; margin-bottom: 0.5rem; }
        .login-container .form-group { 
            margin-bottom: 1.5rem; 
        }
        .login-container .form-group label { 
            display: block; 
            font-size: 0.875rem; 
            font-weight: 600; 
            color: #374151; 
            margin-bottom: 0.5rem; 
        }
        #content-container .form-group label {
            display: block;
            font-size: 0.875rem;
            font-weight: 600;
            color: #374151;
            margin-bottom: 0.5rem;
        }
        #content-container .form-group input,
        #content-container .form-group textarea,
        #content-container .form-group select {
            width: 100%;
            padding: 0.75rem 1rem;
            border: 1px solid var(--color-gray-300);
            border-radius: 0.5rem;
            font-size: 0.9375rem;
            transition: border-color 0.2s, box-shadow 0.2s;
            background-color: var(--color-white);
        }
        #content-container .form-group input:focus,
        #content-container .form-group textarea:focus,
        #content-container .form-group select:focus {
            outline: none;
            border-color: var(--color-indigo-600);
            box-shadow: 0 0 0 3px rgba(79, 70, 229, 0.1);
        }
        /* Style for inputs with icon */
        .input-group {
            position: relative;
            display: flex;
            align-items: center;
        }
        .input-group input {
            padding-left: 2.5rem !important; /* Make space for icon */
        }
        .input-group .input-icon {
            position: absolute;
            left: 0.75rem;
            color: var(--color-gray-500);
            width: 1.25rem;
            height: 1.25rem;
        }
        .login-container .form-group input { 
            width: 100%; padding: 0.75rem 1rem; border: 1px solid #e5e7eb; border-radius: 0.5rem; 
            font-size: 1rem; box-shadow: inset 0 1px 2px 0 rgba(0, 0, 0, 0.05); transition: border-color 0.2s; 
        }
        .otp-input-group input {
            text-align: center;
            font-size: 1.5rem !important;
            letter-spacing: 0.5rem;
            font-weight: 700;
            padding: 0.875rem 1rem !important;
            width: 100%;
        }
        .otp-input-group input:focus {
            outline: none;
            border-color: var(--color-indigo-600);
            box-shadow: 0 0 0 3px rgba(79, 70, 229, 0.1);
        }
        .login-container .form-group input:focus { 
            outline: none; border-color: var(--color-indigo-600); box-shadow: 0 0 0 3px rgba(79, 70, 229, 0.1); 
        }
        .login-container .btn-primary { 
            width: 100%;
        }
        .alert-message { 
            padding: 1rem 1.25rem; 
            border-radius: 0.75rem; 
            margin-bottom: 1.5rem; 
            font-size: 0.875rem; 
            font-weight: 500;
            line-height: 1.5;
            border: 1px solid transparent;
        }
        .alert-success { 
            background-color: #d1fae5; 
            color: var(--color-green-600);
            border-color: rgba(5, 150, 105, 0.2);
        }
        .alert-error { 
            background-color: #fee2e2; 
            color: var(--color-red-600);
            border-color: rgba(220, 38, 38, 0.2);
        }
        .switch-link { margin-top: 1.5rem; text-align: center; font-size: 0.875rem; }
        .switch-link a { color: var(--color-indigo-600); text-decoration: none; font-weight: 600; }
        .switch-link a:hover { text-decoration: underline; }
        .otp-nav {
            display: flex;
            flex-direction: column; /* Changed to column for better mobile stacking */
            gap: 0.75rem; /* Added gap */
            margin-top: 1.5rem;
            font-size: 0.875rem;
        }
        .otp-nav a {
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 0.5rem;
            border-radius: 0.5rem;
            color: var(--color-indigo-600);
            background-color: #f3f4f6;
            text-decoration: none;
            font-weight: 600;
            transition: background-color 0.2s;
        }
        .otp-nav a:hover {
            background-color: #e5e7eb;
            text-decoration: none;
        }
        <?php else: /* --- Admin Dashboard Specific Styles --- */ ?>
        
        .sidebar { 
            width: 260px; 
            flex-shrink: 0; 
            height: 100vh; 
            overflow-y: auto; 
            overflow-x: hidden;
            background: linear-gradient(180deg, #1e293b 0%, #0f172a 100%);
            box-shadow: 4px 0 20px rgba(0, 0, 0, 0.1);
            position: fixed;
            left: 0;
            top: 0;
            z-index: 30;
            display: flex;
            flex-direction: column;
            border-right: 1px solid rgba(255, 255, 255, 0.1);
        }
        .sidebar::-webkit-scrollbar {
            width: 6px;
        }
        .sidebar::-webkit-scrollbar-track {
            background: rgba(255, 255, 255, 0.05);
        }
        .sidebar::-webkit-scrollbar-thumb {
            background: rgba(255, 255, 255, 0.2);
            border-radius: 3px;
        }
        .logo-container { 
            padding: 1.25rem 1rem; 
            display: flex; 
            align-items: center; 
            justify-content: center; 
            min-height: 70px; 
            border-bottom: 1px solid rgba(255, 255, 255, 0.1); 
            margin-bottom: 0;
        }
        .logo-text { color: var(--color-accent-cyan); font-weight: 900; letter-spacing: 0.1em; font-size: 1.25rem; }
        .logo-icon { color: var(--color-white); width: 2rem; height: 2rem; margin-right: 0.5rem; }
        .logo-flex { display: flex; align-items: center; column-gap: 0.5rem; }
        .nav-menu { 
            margin-top: 0.5rem; 
            padding: 0.5rem 0.75rem; 
            display: flex; 
            flex-direction: column; 
            row-gap: 0.25rem;
            flex-grow: 1;
            padding-bottom: 1rem;
        }
        .nav-item { 
            display: flex; 
            align-items: center; 
            padding: 0.875rem 1rem; 
            border-radius: 0.5rem; 
            font-size: 0.875rem; 
            font-weight: 500; 
            color: rgba(255, 255, 255, 0.85); 
            text-decoration: none; 
            transition: all 0.2s; 
            position: relative; 
        }
        .nav-item i {
            width: 1.25rem;
            height: 1.25rem;
            margin-right: 0.75rem;
            opacity: 0.9;
        }
        .nav-item:hover { 
            background-color: rgba(255, 255, 255, 0.1); 
            color: var(--color-white); 
        }
        .active-nav { 
            background-color: var(--color-primary-dark); 
            color: var(--color-white);
            font-weight: 600;
        }
        .active-nav i {
            opacity: 1;
        }
        .submenu { 
            padding-left: 2.5rem; 
            padding-top: 0.5rem; 
            padding-bottom: 0.25rem;
            display: flex; 
            flex-direction: column; 
            row-gap: 0.25rem; 
        }
        .submenu a { 
            display: block; 
            color: rgba(255, 255, 255, 0.7); 
            font-size: 0.8125rem; 
            padding: 0.5rem 0.75rem; 
            border-radius: 0.375rem;
            text-decoration: none; 
            transition: all 0.2s;
        }
        .submenu a:hover { 
            color: var(--color-white); 
            background-color: rgba(255, 255, 255, 0.05);
        }
        .sidebar-footer {
            position: sticky;
            bottom: 0;
            left: 0;
            right: 0;
            padding: 1rem;
            text-align: center;
            font-size: 0.75rem;
            color: rgba(255, 255, 255, 0.5);
            border-top: 1px solid rgba(255, 255, 255, 0.1);
            background-color: var(--color-dark-grey);
            margin-top: auto;
        }

        .main-content { 
            flex: 1; 
            overflow-x: hidden; 
            overflow-y: auto; 
            background-color: var(--color-background); 
            margin-left: 260px;
            min-height: 100vh;
        }
        .main-header { 
            background: linear-gradient(135deg, var(--color-white) 0%, #f8fafc 100%);
            backdrop-filter: blur(10px);
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.05); 
            min-height: 75px; 
            display: flex; 
            align-items: center; 
            justify-content: space-between;
            padding: 0 2rem; 
            position: sticky; 
            top: 0; 
            z-index: 20; 
            border-bottom: 1px solid rgba(226, 232, 240, 0.8);
        }
        /* Hiding mobile title on large screens */
        .header-title { 
            font-size: 1.5rem; 
            font-weight: 700; 
            color: #1f2937; 
            padding-left: 0;
            margin: 0;
            display: none; 
        }
        .page-title-container {
            flex-grow: 1;
            display: none;
        }

        .header-right { 
            display: flex; 
            align-items: center; 
            justify-content: flex-end;
            column-gap: 1rem;
            margin-left: auto;
        }
        .header-right .profile-avatar {
            border: 2px solid rgba(255, 255, 255, 0.3);
            transition: all 0.3s ease;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
        }
        .header-right .profile-avatar:hover {
            transform: scale(1.1);
            box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -2px rgba(0, 0, 0, 0.05);
            border-color: rgba(255, 255, 255, 0.5);
        }
        
        /* Profile Dropdown Styling */
        .profile-menu-container { 
            position: relative; 
            cursor: pointer;
        }
        .profile-menu-container:focus {
            outline: none;
        }
        .profile-dropdown {
            position: absolute;
            top: 100%;
            right: 0;
            margin-top: 0.75rem;
            width: 220px;
            background-color: var(--color-white);
            border-radius: 0.75rem;
            box-shadow: var(--shadow-lg);
            border: 1px solid var(--color-gray-300);
            overflow: hidden;
            z-index: 20;
            padding: 0.5rem 0;
            display: none;
        }
        .profile-menu-container:focus .profile-dropdown,
        .profile-menu-container:focus-within .profile-dropdown {
            display: block;
        }
        .profile-dropdown a {
            display: flex;
            align-items: center;
            padding: 0.5rem 1rem;
            font-size: 0.875rem;
            color: #4b5563;
            text-decoration: none;
            transition: background-color 0.15s;
        }
        .profile-dropdown a:hover {
            background-color: #f3f4f6;
        }
        .profile-dropdown .divider {
            height: 1px;
            background-color: #e5e7eb;
            margin: 0.5rem 0;
        }

        /* Adjusted Padding for Content Container to fix alignment with header */
        #content-container { 
            padding: 2rem 2.5rem; 
            max-width: 1400px;
            margin: 0 auto;
        }
        .page-header { 
            font-size: 2rem; 
            font-weight: 700; 
            color: #111827; 
            margin-bottom: 2rem; 
            letter-spacing: -0.025em;
        }
        .kpi-card-grid { 
            display: grid; 
            grid-template-columns: 1fr; 
            gap: 1.5rem; 
            margin-bottom: 2rem; 
        }
        .kpi-card { 
            background: linear-gradient(135deg, var(--color-white) 0%, #f8fafc 100%);
            padding: 1.75rem; 
            border-radius: 1.25rem; 
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.08);
            border: 1px solid rgba(226, 232, 240, 0.8);
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            position: relative;
            overflow: hidden;
        }
        .kpi-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: linear-gradient(90deg, var(--color-primary) 0%, var(--color-accent-cyan) 100%);
            opacity: 0;
            transition: opacity 0.3s;
        }
        .kpi-card:hover {
            transform: translateY(-4px) scale(1.02);
            box-shadow: 0 12px 40px rgba(0, 0, 0, 0.12);
            border-color: var(--color-primary);
        }
        .kpi-card:hover::before {
            opacity: 1;
        }
        .kpi-card.p-6 {
            padding: 1.75rem !important;
        }
        .module-container {
            display: grid;
            gap: 1.5rem;
        }
        h3.text-xl {
            font-size: 1.25rem;
            font-weight: 600;
            color: #1f2937;
            margin-bottom: 1rem;
        }
        .text-gray-500 {
            color: var(--color-gray-500);
        }
        .mb-6 {
            margin-bottom: 1.5rem;
        }
        .mb-4 {
            margin-bottom: 1rem;
        }
        .mt-4 {
            margin-top: 1rem;
        }
        .mt-6 {
            margin-top: 1.5rem;
        }
        /* KPI Colors */
        .kpi-green .card-value, .kpi-green .card-icon i { color: var(--color-green-600); }
        .kpi-green .card-icon { 
            background: linear-gradient(135deg, #d1fae5 0%, #a7f3d0 100%);
            box-shadow: 0 4px 12px rgba(5, 150, 105, 0.2);
        } 
        .kpi-indigo .card-value, .kpi-indigo .card-icon i { color: var(--color-indigo-600); }
        .kpi-indigo .card-icon { 
            background: linear-gradient(135deg, #e0e7ff 0%, #c7d2fe 100%);
            box-shadow: 0 4px 12px rgba(79, 70, 229, 0.2);
        } 
        .kpi-red .card-value, .kpi-red .card-icon i { color: var(--color-red-600); }
        .kpi-red .card-icon { 
            background: linear-gradient(135deg, #fee2e2 0%, #fecaca 100%);
            box-shadow: 0 4px 12px rgba(220, 38, 38, 0.2);
        } 
        .kpi-yellow .card-value, .kpi-yellow .card-icon i { color: var(--color-yellow-600); }
        .kpi-yellow .card-icon { 
            background: linear-gradient(135deg, #fef3c7 0%, #fde68a 100%);
            box-shadow: 0 4px 12px rgba(217, 119, 6, 0.2);
        } 
        
        .data-table { 
            width: 100%; 
            border-collapse: collapse; 
            table-layout: auto; 
            min-width: 600px; 
            background-color: var(--color-white);
            border-radius: 1rem;
            overflow: hidden;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.06);
        }
        .data-table thead tr { 
            font-size: 0.75rem; 
            font-weight: 700; 
            text-align: left; 
            text-transform: uppercase; 
            letter-spacing: 0.08em;
            color: var(--color-gray-500); 
            background: linear-gradient(135deg, #f8fafc 0%, #f1f5f9 100%);
            border-bottom: 2px solid var(--color-gray-200); 
        }
        .data-table th, .data-table td { 
            padding: 1rem 1.5rem; 
        }
        .data-table th {
            font-weight: 600;
        }
        .data-table td {
            white-space: nowrap;
            color: #374151;
        }
        .data-table tbody tr { 
            border-top: 1px solid var(--color-gray-300); 
            transition: background-color 0.15s;
        }
        .data-table tbody tr:hover { 
            background: linear-gradient(90deg, #f8fafc 0%, #f1f5f9 100%);
            transform: scale(1.01);
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.05);
        }
        .table-container {
            overflow-x: auto;
            border-radius: 0.75rem;
            box-shadow: var(--shadow-sm);
        }

        /* Status Badges */
        .status-badge {
            display: inline-flex;
            align-items: center;
            padding: 0.375rem 0.75rem; 
            font-size: 0.75rem; 
            line-height: 1.25; 
            font-weight: 700; 
            border-radius: 9999px; 
            text-transform: uppercase;
            letter-spacing: 0.05em;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
            transition: all 0.2s;
        }
        .status-badge.active, .status-badge.delivered, .status-badge.verified { 
            background: linear-gradient(135deg, #d1fae5 0%, #a7f3d0 100%);
            color: var(--color-green-600);
            box-shadow: 0 2px 8px rgba(5, 150, 105, 0.3);
        } 
        .status-badge.low-stock, .status-badge.pending, .status-badge.requires-review { 
            background: linear-gradient(135deg, #fef3c7 0%, #fde68a 100%);
            color: #92400e;
            box-shadow: 0 2px 8px rgba(217, 119, 6, 0.3);
        } 
        .status-badge.critical-stock, .status-badge.cancelled, .status-badge.inactive { 
            background: linear-gradient(135deg, #fee2e2 0%, #fecaca 100%);
            color: var(--color-red-600);
            box-shadow: 0 2px 8px rgba(220, 38, 38, 0.3);
        } 
        .status-badge.processing, .status-badge.in-transit { 
            background: linear-gradient(135deg, #dbeafe 0%, #bfdbfe 100%);
            color: #1e40af;
            box-shadow: 0 2px 8px rgba(30, 64, 175, 0.3);
        } 
        .status-badge.shipped, .status-badge.out-for-delivery { 
            background: linear-gradient(135deg, #e0e7ff 0%, #c7d2fe 100%);
            color: #3730a3;
            box-shadow: 0 2px 8px rgba(79, 70, 229, 0.3);
        }
        .status-badge:hover {
            transform: scale(1.05);
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
        }
        
        /* Enhanced animations */
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        .kpi-card {
            animation: fadeIn 0.3s ease-out;
        }
        
        /* Improved table hover effects */
        .data-table tbody tr {
            transition: all 0.2s ease;
        }
        
        .data-table tbody tr:hover {
            background-color: #f9fafb;
            transform: scale(1.01);
            box-shadow: 0 2px 8px rgba(0,0,0,0.05);
        }
        
        /* Better button hover effects */
        .btn-base {
            transition: all 0.2s ease;
        }
        
        .btn-base:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        }
        
        .btn-base:active {
            transform: translateY(0);
        } 
        
        @media (min-width: 768px) { 
            .kpi-card-grid { 
                grid-template-columns: repeat(2, 1fr); 
            } 
        }
        @media (min-width: 1024px) { 
            .kpi-card-grid { 
                grid-template-columns: repeat(4, 1fr); 
            } 
        }
        @media (max-width: 768px) {
            .sidebar {
                width: 240px;
            }
            .main-content {
                margin-left: 240px;
            }
            #content-container {
                padding: 1.5rem;
            }
        }

        <?php endif; ?>
        .hidden { display: none !important; }
        
    </style>
</head>

<?php if (!$is_logged_in): ?>
<!-- ========================================================================= -->
<!-- LOGIN / REGISTER / OTP PORTAL HTML -->
<!-- ========================================================================= -->
<body>
    <div class="login-container">
        <div class="header">
            <i data-lucide="<?php echo $is_otp_page ? 'shield-check' : ($is_register_page ? 'user-plus' : 'lock'); ?>" class="logo-icon"></i>
            <span class="logo-text">iMARKET ADMIN <?php echo $is_otp_page ? 'VERIFICATION' : ($is_register_page ? 'REGISTRATION' : 'LOGIN'); ?></span>
            <p style="color: var(--color-gray-500); font-size: 0.875rem; margin-top: 0.5rem;">
                <?php 
                    if ($is_otp_page) {
                        // UPDATED TEXT: Email
                        echo "Enter the 6-digit code sent to your **Email Address** to continue login for **{$admin_username}**.";
                    } else if ($is_register_page) {
                        echo 'Create your new administrator account. **Full Name and Email Address are required for OTP login.**';
                    } else {
                        // UPDATED TEXT: Email
                        echo 'Enter your credentials to access the portal. **Email OTP verification is required for login.**';
                    }
                ?>
            </p>
        </div>
        
        <?php if ($message): ?>
            <div class="alert-message <?php echo strpos($message, 'successful') !== false || strpos($message, 'DEMO CODE') !== false ? 'alert-success' : 'alert-error'; ?>">
                <?php echo htmlspecialchars($message); ?>
            </div>
        <?php endif; ?>

        <?php if ($is_otp_page): ?>
            <!-- OTP Verification Form (NEW) -->
            <form method="POST" action="<?php echo basename(__FILE__); ?>" id="otp-form">
                <input type="hidden" name="action" value="otp_verify">
                <input type="hidden" name="user_id" value="<?php echo $_SESSION['temp_admin_id'] ?? ''; ?>">
                
                <div class="form-group otp-input-group">
                    <label for="otp_code">OTP Code (6 Digits)</label>
                    <input type="text" id="otp_code" name="otp_code" required maxlength="6" minlength="6" pattern="[0-9]{6}" 
                            placeholder="000000" autocomplete="one-time-code" inputmode="numeric"
                            style="text-align: center; font-size: 1.5rem !important; letter-spacing: 0.5rem; font-weight: 700; padding-left: 1rem !important;"
                            oninput="this.value = this.value.replace(/[^0-9]/g, ''); if(this.value.length > 6) this.value = this.value.slice(0, 6);"
                            onpaste="this.value = this.value.replace(/[^0-9]/g, '').slice(0, 6);">
                    <p style="font-size: 0.75rem; color: var(--color-gray-500); margin-top: 0.5rem; text-align: center;">
                        Enter the 6-digit code sent to your email
                    </p>
                    <?php if (isset($_SESSION['temp_admin_username'])): ?>
                    <p style="font-size: 0.75rem; color: var(--color-indigo-600); margin-top: 0.25rem; text-align: center; font-weight: 600;">
                        Verifying for: <?php echo htmlspecialchars($_SESSION['temp_admin_username']); ?>
                    </p>
                    <?php endif; ?>
                    <?php 
                    // Debug: Show the OTP code in development (remove in production)
                    // Uncomment the line below if you need to see the OTP for testing
                    // if (isset($_SESSION['temp_admin_id'])) {
                    //     $debug_user = get_admin_user_details($pdo, $_SESSION['temp_admin_id']);
                    //     if ($debug_user && !empty($debug_user['otp_code'])) {
                    //         echo '<p style="font-size: 0.7rem; color: var(--color-red-600); margin-top: 0.25rem; text-align: center; font-weight: 700; background: #fee2e2; padding: 0.5rem; border-radius: 0.25rem;">DEBUG: OTP Code is ' . htmlspecialchars($debug_user['otp_code']) . '</p>';
                    //     }
                    // }
                    ?>
                </div>
                
                <button type="submit" class="btn-base btn-primary w-full">
                    <i data-lucide="shield-check" style="width: 1rem; height: 1rem; margin-right: 0.5rem;"></i>
                    Verify & Log In
                </button>
            </form>
            
            <script>
                // Auto-focus and validation for OTP input
                document.addEventListener('DOMContentLoaded', function() {
                    const otpInput = document.getElementById('otp_code');
                    const otpForm = document.getElementById('otp-form');
                    
                    if (otpInput) {
                        // Focus on the input field
                        otpInput.focus();
                        
                        // Ensure only numbers are entered
                        otpInput.addEventListener('input', function() {
                            // Remove any non-numeric characters
                            this.value = this.value.replace(/[^0-9]/g, '');
                            
                            // Limit to 6 digits
                            if (this.value.length > 6) {
                                this.value = this.value.slice(0, 6);
                            }
                            
                            // Enable/disable submit button based on length
                            const submitBtn = otpForm.querySelector('button[type="submit"]');
                            if (submitBtn) {
                                if (this.value.length === 6) {
                                    submitBtn.disabled = false;
                                    submitBtn.style.opacity = '1';
                                } else {
                                    submitBtn.disabled = false; // Keep enabled but validate on submit
                                }
                            }
                        });
                        
                        // Handle paste events
                        otpInput.addEventListener('paste', function(e) {
                            e.preventDefault();
                            const pastedData = (e.clipboardData || window.clipboardData).getData('text');
                            const numbersOnly = pastedData.replace(/[^0-9]/g, '').slice(0, 6);
                            this.value = numbersOnly;
                            this.dispatchEvent(new Event('input'));
                        });
                        
                        // Form validation before submit
                        otpForm.addEventListener('submit', function(e) {
                            const otpValue = otpInput.value.replace(/[^0-9]/g, '');
                            
                            if (otpValue.length !== 6) {
                                e.preventDefault();
                                alert('Please enter exactly 6 digits for the OTP code. You entered ' + otpValue.length + ' digit(s).');
                                otpInput.focus();
                                return false;
                            }
                            
                            // Ensure only numeric value is submitted (no padding needed)
                            otpInput.value = otpValue;
                        });
                    }
                });
            </script>
            
            <!-- NEW: Navigation links to return to login or register -->
            <div class="otp-nav">
                <!-- Option 1: Mag-Log In Ulit (Generate Bagong OTP) -->
                <a href="?action=return_to_login">
                    <i data-lucide="refresh-cw" style="width: 1rem; height: 1rem; margin-right: 0.25rem;"></i>
                    Re-attempt Login (New OTP)
                </a>
                
                <!-- Option 2: Gumawa ng Bagong Account -->
                <a href="<?php echo basename(__FILE__); ?>?view=register" onclick="event.preventDefault(); window.location.href='?action=return_to_login&view=register';">
                    <i data-lucide="user-plus" style="width: 1rem; height: 1rem; margin-right: 0.25rem;"></i>
                    Create New Account
                </a>
            </div>
            
        <?php elseif ($is_register_page): ?>
            <!-- Registration Form (UPDATED with icons) -->
            <form method="POST" action="<?php echo basename(__FILE__); ?>">
                <input type="hidden" name="action" value="register">
                
                <!-- NEW FIELD: Full Name -->
                <div class="form-group">
                    <label for="full_name">Full Name</label>
                    <div class="input-group">
                        <i data-lucide="user" class="input-icon"></i>
                        <input type="text" id="full_name" name="full_name" required autocomplete="name" placeholder="E.g., Juan Dela Cruz">
                    </div>
                </div>
                
                <div class="form-group">
                    <label for="username">Username</label>
                    <div class="input-group">
                        <i data-lucide="user-check" class="input-icon"></i>
                        <input type="text" id="username" name="username" required autocomplete="new-username">
                    </div>
                </div>
                
                <div class="form-group">
                    <label for="email">Email Address (Used for OTP)</label>
                    <div class="input-group">
                        <i data-lucide="mail" class="input-icon"></i>
                        <input type="email" id="email" name="email" required autocomplete="email" placeholder="e.g. admin@example.com">
                    </div>
                </div>

                <div class="form-group">
                    <label for="phone_number">Mobile Number (Optional Contact)</label>
                    <div class="input-group">
                        <i data-lucide="phone" class="input-icon"></i>
                        <input type="tel" id="phone_number" name="phone_number" autocomplete="tel" placeholder="E.g., 09xxxxxxxxx (Not used for OTP)">
                    </div>
                </div>
                
                <div class="form-group">
                    <label for="password">Password (Min 6 Characters)</label>
                    <div class="input-group">
                        <i data-lucide="key" class="input-icon"></i>
                        <input type="password" id="password" name="password" required autocomplete="new-password">
                    </div>
                </div>
                
                <!-- NEW FIELD: Confirm Password -->
                <div class="form-group">
                    <label for="confirm_password">Confirm Password</label>
                    <div class="input-group">
                        <i data-lucide="key-round" class="input-icon"></i>
                        <input type="password" id="confirm_password" name="confirm_password" required autocomplete="new-password">
                    </div>
                </div>
                
                <button type="submit" class="btn-base btn-primary">
                    <i data-lucide="user-plus" style="width: 1rem; height: 1rem; margin-right: 0.5rem;"></i>
                    Create Account
                </button>
            </form>
            <p class="switch-link">
                Already have an account? <a href="<?php echo basename(__FILE__); ?>">Log In</a>
            </p>
        <?php else: ?>
            <!-- Login Form (Original with icons) -->
            <form method="POST" action="<?php echo basename(__FILE__); ?>">
                <input type="hidden" name="action" value="login">
                <div class="form-group">
                    <label for="username">Username</label>
                    <div class="input-group">
                        <i data-lucide="user" class="input-icon"></i>
                        <input type="text" id="username" name="username" required autocomplete="username">
                    </div>
                </div>
                
                <div class="form-group">
                    <label for="password">Password</label>
                    <div class="input-group">
                        <i data-lucide="lock" class="input-icon"></i>
                        <input type="password" id="password" name="password" required autocomplete="current-password">
                    </div>
                </div>
                
                <button type="submit" class="btn-base btn-primary">
                    <i data-lucide="log-in" style="width: 1rem; height: 1rem; margin-right: 0.5rem;"></i>
                    Log In
                </button>
            </form>
            <p class="switch-link">
                Don't have an account? <a href="<?php echo basename(__FILE__); ?>?view=register">Create Account</a>
            </p>
        <?php endif; ?>
    </div>
    
    <script>
        lucide.createIcons();
    </script>
</body>
</html>

<?php else: 
// =========================================================================
// ADMIN DASHBOARD HTML (If logged in)
// =========================================================================
?>

<body>

    <!-- Sidebar / Navigation -->
    <aside id="sidebar" class="sidebar">
        <div class="logo-container">
            <div class="logo-flex">
                <svg class="logo-icon" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                    <path d="M12 2L2 8.5V15.5L12 22L22 15.5V8.5L12 2Z" fill="#4bc5ec" stroke="#94dcf4" stroke-width="1"/>
                    <path d="M12 2L12 22" stroke="#2c3c8c" stroke-width="2"/>
                    <path d="M2 8.5L22 15.5" stroke="#2c3c8c" stroke-width="2"/>
                    <path d="M2 15.5L22 8.5" stroke="#2c3c8c" stroke-width="2"/>
                    <polyline points="5 12 10 17 19 8" stroke="#ffffff" stroke-width="2" fill="none"/>
                </svg>
                <span class="logo-text">iMARKET</span>
            </div>
        </div>

        <nav class="nav-menu">
            <a href="#" class="nav-item active-nav" onclick="showModule('dashboard', this)">
                <i data-lucide="layout-dashboard" class="w-5 h-5 mr-3"></i>
                Dashboard & Analytics
            </a>
            <div class="group">
                <a href="#" class="nav-item" onclick="toggleSubMenu(this, 'product-submenu'); showSubModule('product', 'products');">
                    <i data-lucide="package" class="w-5 h-5 mr-3"></i>
                    Product & Storefront
                    <i data-lucide="chevron-right" class="w-4 h-4 ml-auto transition-transform duration-200 chevron-icon"></i>
                </a>
                <div id="product-submenu" class="submenu hidden">
                    <a href="#" onclick="showSubModule('product', 'products'); event.preventDefault();">Product List</a>
                    <a href="#" onclick="showSubModule('product', 'categories'); event.preventDefault();">Category Management</a>
                    <a href="#" onclick="showSubModule('product', 'storefront'); event.preventDefault();">Storefront Preview</a>
                </div>
            </div>

            <div class="group">
                <a href="#" class="nav-item" onclick="toggleSubMenu(this, 'order-submenu'); showSubModule('order', 'orders');">
                    <i data-lucide="shopping-cart" class="w-5 h-5 mr-3"></i>
                    Order & Checkout
                    <i data-lucide="chevron-right" class="w-4 h-4 ml-auto transition-transform duration-200 chevron-icon"></i>
                </a>
                <div id="order-submenu" class="submenu hidden">
                    <a href="#" onclick="showSubModule('order', 'orders'); event.preventDefault();">View All Orders</a>
                    <a href="#" onclick="showSubModule('order', 'payments'); event.preventDefault();">Transaction Logs</a>
                </div>
            </div>

            <div class="group">
                <a href="#" class="nav-item" onclick="toggleSubMenu(this, 'shipping-submenu'); showSubModule('shipping', 'addresses');">
                    <i data-lucide="truck" class="w-5 h-5 mr-3"></i>
                    Shipping & Address
                    <i data-lucide="chevron-right" class="w-4 h-4 ml-auto transition-transform duration-200 chevron-icon"></i>
                </a>
                <div id="shipping-submenu" class="submenu hidden">
                    <a href="#" onclick="showSubModule('shipping', 'addresses'); event.preventDefault();">Addresses & Validation</a>
                    <a href="#" onclick="showSubModule('shipping', 'tracking'); event.preventDefault();">Shipment Tracking</a>
                </div>
            </div>

            <div class="group">
                <a href="#" class="nav-item" onclick="toggleSubMenu(this, 'user-submenu'); showSubModule('user', 'profile');">
                    <i data-lucide="users" class="w-5 h-5 mr-3"></i>
                    User & Roles
                    <i data-lucide="chevron-right" class="w-4 h-4 ml-auto transition-transform duration-200 chevron-icon"></i>
                </a>
                <div id="user-submenu" class="submenu hidden">
                    <a href="#" onclick="showSubModule('user', 'profile'); event.preventDefault();">Admin Profile</a> 
                    <a href="#" onclick="showSubModule('user', 'admins'); event.preventDefault();">Admin Accounts</a>
                    <a href="#" onclick="showSubModule('user', 'customers'); event.preventDefault();">Customer List</a>
                </div>
            </div>

            <a href="#" class="nav-item" onclick="showModule('support', this)">
                <i data-lucide="message-square" class="w-5 h-5 mr-3"></i>
                Customer Support Center
            </a>

            <a href="#" class="nav-item" onclick="showModule('alerts', this)">
                <i data-lucide="alert-triangle" class="w-5 h-5 mr-3"></i>
                Notifications & Alerts
            </a>
            
            <a href="#" class="nav-item" onclick="showModule('settings', this)">
                <i data-lucide="settings" class="w-5 h-5 mr-3"></i>
                System Settings & Security
            </a>
        </nav>

        <div class="sidebar-footer">
            <p>iMARKET Admin Portal v1.0</p>
        </div>
    </aside>

    <!-- Main Content Area -->
    <main class="main-content">
        <header class="main-header">
            <!-- Pangkalahatang Tanaw title area -->
            <div class="page-title-container">
                <!-- H1 is hidden on large screens to avoid layout duplication with H2 in content -->
                <h1 class="header-title" id="page-title">Dashboard & Analytics</h1>
            </div>
            
            <div class="header-right">
                <div class="profile-menu-container" tabindex="0">
                    <div class="profile-avatar" style="width: 2.5rem; height: 2.5rem; border-radius: 50%; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); display: flex; align-items: center; justify-content: center; color: white; font-weight: 700; font-size: 1rem; cursor: pointer; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06); transition: all 0.2s; border: 2px solid rgba(255, 255, 255, 0.2);">
                        <?php echo strtoupper(substr($admin_username, 0, 1)); ?>
                    </div>
                    
                    <div class="profile-dropdown">
                        <div style="padding: 0.75rem 1rem; color: #1f2937; font-weight: 600; border-bottom: 1px solid #f9fafb;">
                            <?php echo $admin_username; ?> 
                            <span class="text-xs font-medium" style="display: block; color: var(--color-indigo-600); margin-top: 0.25rem;"><?php echo $admin_role; ?></span>
                        </div>
                        <a href="#" onclick="showSubModule('user', 'profile'); event.preventDefault();">
                            <i data-lucide="user-cog" style="width: 1.1rem; height: 1.1rem; margin-right: 0.75rem;"></i>
                            Admin Profile
                        </a>
                        <div class="divider"></div>
                        <a href="<?php echo basename(__FILE__); ?>?action=logout" style="color: var(--color-red-600);">
                            <i data-lucide="log-out" style="width: 1.1rem; height: 1.1rem; margin-right: 0.75rem;"></i>
                            Log Out
                        </a>
                    </div>
                </div>
            </div>
        </header>

        <!-- Module Content Container -->
        <div id="content-container">
            <!-- Dynamic content will be loaded here -->
        </div>
    </main>

    <!-- Custom Modal/Message Box (Replaces alert()/confirm()) -->
    <div id="custom-modal-backdrop" class="modal-backdrop hidden">
        <div id="modal-container" class="modal-content">
            <!-- Content dynamically injected here -->
        </div>
    </div>


    <script>
        // Initialize Lucide Icons
        lucide.createIcons();

        // --- PLACEHOLDER DATA ---
        const formatCurrency = (amount) => {
            return new Intl.NumberFormat('en-US', { style: 'currency', currency: 'USD' }).format(amount);
        };
        
        // Inject data from PHP
        const kpiData = <?php echo json_encode($kpi_data); ?>;
        const productsData = <?php echo json_encode($mock_products); ?>;
        const ordersData = <?php echo json_encode($mock_orders); ?>;
        const adminDetails = <?php echo json_encode($admin_details); ?>;
        const categoriesData = <?php echo json_encode($mock_categories); ?>;
        const transactionsData = <?php echo json_encode($mock_transactions); ?>;
        const shipmentsData = <?php echo json_encode($mock_shipments); ?>;
        const customersData = <?php echo json_encode($mock_customers); ?>;
        const supportTicketsData = <?php echo json_encode($mock_support_tickets); ?>;
        const adminUsersData = <?php echo json_encode($mock_admin_users); ?>;
        
        // Use PHP to safely inject the addresses array
        const mockAddresses = <?php echo json_encode($mockAddresses); ?>;

        
        // --- UTILITY FUNCTIONS ---
        function setPageTitle(title) {
            // Update the large title in the content area
            const contentHeader = document.querySelector('#content-container .page-header');
            if (contentHeader) {
                contentHeader.innerText = title;
            }
            // Update the invisible title used in the header bar for alignment
            document.getElementById('page-title').innerText = title;
        }

        function setActiveNav(element) {
            // Reset all nav items
            document.querySelectorAll('.nav-menu a').forEach(item => {
                item.classList.remove('active-nav');
                // Also reset rotation on chevron icons
                const icon = item.querySelector('.chevron-icon');
                if (icon) {
                    icon.classList.remove('rotate-90');
                }
            });
            // Set the main element to active
            element.classList.add('active-nav');
        }

        function toggleSubMenu(element, submenuId) {
            const submenu = document.getElementById(submenuId);
            const icon = element.querySelector('.chevron-icon');
            
            submenu.classList.toggle('hidden');
            icon.classList.toggle('rotate-90');

            event.preventDefault();
        }
        
        // Custom Modal Implementation (Replaces alert/confirm)
        function showCustomActionModal(title, message, confirmText = 'OK', actionCallback = null) {
            const backdrop = document.getElementById('custom-modal-backdrop');
            const modalContainer = document.getElementById('modal-container');

            // Simple markup for bolding **text**
            const safeMessage = message
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;')
                .replace(/\*\*(.*?)\*\*/g, '<b>$1</b>');

            modalContainer.innerHTML = `
                <h3 id="modal-title" class="modal-title" style="font-size: 1.25rem; font-weight: 700; color: #1f2937;">${title}</h3>
                <p id="modal-message" class="modal-message" style="font-size: 1rem; color: var(--color-gray-500); margin-bottom: 1.5rem;">${safeMessage}</p>
                <div class="modal-actions" style="display: flex; justify-content: flex-end; column-gap: 0.75rem;">
                    <button id="modal-cancel" class="btn-base btn-secondary hidden">Cancel</button>
                    <button id="modal-confirm" class="btn-base btn-primary">${confirmText}</button>
                </div>
            `;
            
            const confirmBtn = document.getElementById('modal-confirm');
            const cancelBtn = document.getElementById('modal-cancel');

            if (actionCallback) {
                cancelBtn.classList.remove('hidden');
                cancelBtn.onclick = () => backdrop.classList.add('hidden');
                confirmBtn.onclick = () => {
                    actionCallback();
                    backdrop.classList.add('hidden');
                };
            } else {
                cancelBtn.classList.add('hidden');
                confirmBtn.onclick = () => backdrop.classList.add('hidden');
            }

            backdrop.classList.remove('hidden');
        }
        
        // --- MAIN CONTENT FUNCTIONS (MODULES - ENHANCED) ---

        // Helper function for KPI Card HTML
        function createKPICard(title, value, iconName, kpiClass) {
            return `
                <div class="kpi-card ${kpiClass}">
                    <div class="card-content" style="display: flex; align-items: center; justify-content: space-between;">
                        <div style="flex: 1;">
                            <p class="card-title" style="font-size: 0.875rem; font-weight: 600; color: var(--color-gray-500); margin-bottom: 0.5rem; text-transform: uppercase; letter-spacing: 0.05em;">${title}</p>
                            <h2 class="card-value" style="font-size: 2rem; font-weight: 800; line-height: 1.2; margin: 0;">${value}</h2>
                        </div>
                        <div class="card-icon" style="padding: 1rem; border-radius: 1rem; width: 4.5rem; height: 4.5rem; display: flex; align-items: center; justify-content: center; transition: transform 0.3s;">
                            <i data-lucide="${iconName}" style="width: 2rem; height: 2rem;"></i>
                        </div>
                    </div>
                </div>
            `;
        }

        // 4. Dashboard & Analytics
        function renderDashboard() {
            setPageTitle('Dashboard & Analytics');
            const totalRevenue = kpiData.totalRevenue ? formatCurrency(kpiData.totalRevenue) : formatCurrency(0);
            const totalOrders = kpiData.totalOrders || 0;
            const lowStockCount = kpiData.lowStockCount || 0;
            const newCustomers = kpiData.newCustomers || 0;
            const topProducts = kpiData.topProducts || [];

            const topProductsRows = topProducts.map(p => `
                <tr>
                    <td style="color: #1f2937; font-weight: 500;">${p.name}</td>
                    <td>${p.category}</td>
                    <td>${p.sold}</td>
                </tr>
            `).join('');

            const content = document.getElementById('content-container');

            content.innerHTML = `
                <h2 class="page-header">Overview (Real-Time Data)</h2>
                <div class="kpi-card-grid">
                    ${createKPICard('Monthly Revenue', totalRevenue, 'dollar-sign', 'kpi-green')}
                    ${createKPICard('Total Orders (Month)', totalOrders, 'shopping-cart', 'kpi-indigo')}
                    ${createKPICard('Low Stock Alert (<10)', lowStockCount, 'alert-triangle', lowStockCount > 0 ? 'kpi-red' : 'kpi-green')}
                    ${createKPICard('New Customers (Month)', newCustomers, 'users', 'kpi-yellow')}
                </div>
                <div class="dashboard-grid module-container" style="display: grid; grid-template-columns: repeat(auto-fit, minmax(400px, 1fr)); gap: 1.5rem;">
                    <!-- Sales Report Card -->
                    <div class="kpi-card p-6">
                        <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 1.5rem;">
                            <h3 class="text-xl font-semibold" style="color: #0f172a; margin: 0;">Sales Trends</h3>
                            <i data-lucide="trending-up" style="width: 1.5rem; height: 1.5rem; color: var(--color-green-600);"></i>
                        </div>
                        <div style="height: 200px; background: linear-gradient(135deg, #f8fafc 0%, #e2e8f0 100%); display: flex; align-items: center; justify-content: center; border-radius: 0.75rem; border: 2px dashed var(--color-gray-300); margin-bottom: 1rem;">
                            <div style="text-align: center;">
                                <i data-lucide="bar-chart-3" style="width: 3rem; height: 3rem; color: var(--color-gray-400); margin-bottom: 0.5rem;"></i>
                                <p style="color: var(--color-gray-500); font-size: 0.875rem; font-weight: 600;">Chart visualization area</p>
                                <p style="color: var(--color-gray-400); font-size: 0.75rem; margin-top: 0.25rem;">Monthly revenue: ${totalRevenue}</p>
                            </div>
                        </div>
                        <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 1rem; margin-top: 1rem;">
                            <div style="padding: 0.75rem; background: var(--color-gray-100); border-radius: 0.5rem;">
                                <p style="font-size: 0.75rem; color: var(--color-gray-500); margin: 0 0 0.25rem 0;">Conversion Rate</p>
                                <p style="font-size: 1.125rem; font-weight: 700; color: #0f172a; margin: 0;">${((totalOrders / Math.max(newCustomers, 1)) * 100).toFixed(1)}%</p>
                            </div>
                            <div style="padding: 0.75rem; background: var(--color-gray-100); border-radius: 0.5rem;">
                                <p style="font-size: 0.75rem; color: var(--color-gray-500); margin: 0 0 0.25rem 0;">Avg Order Value</p>
                                <p style="font-size: 1.125rem; font-weight: 700; color: #0f172a; margin: 0;">${totalOrders > 0 ? formatCurrency(kpiData.totalRevenue / totalOrders) : formatCurrency(0)}</p>
                            </div>
                        </div>
                    </div>
                    <!-- Current Alerts Card -->
                    <div class="kpi-card p-6">
                        <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 1.5rem;">
                            <h3 class="text-xl font-semibold" style="color: #0f172a; margin: 0;">System Alerts</h3>
                            <i data-lucide="bell" style="width: 1.5rem; height: 1.5rem; color: ${lowStockCount > 0 ? 'var(--color-red-600)' : 'var(--color-green-600)'};"></i>
                        </div>
                        ${lowStockCount > 0 ? `
                            <div style="padding: 1rem; background: linear-gradient(135deg, #fee2e2 0%, #fecaca 100%); border-radius: 0.75rem; border-left: 4px solid var(--color-red-600); margin-bottom: 0.75rem;">
                                <div style="display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.5rem;">
                                    <i data-lucide="alert-triangle" style="width: 1.25rem; height: 1.25rem; color: var(--color-red-600);"></i>
                                    <p style="font-weight: 700; color: var(--color-red-600); margin: 0; font-size: 0.875rem;">Low Stock Alert</p>
                                </div>
                                <p style="color: #991b1b; font-size: 0.875rem; margin: 0;">${lowStockCount} product${lowStockCount > 1 ? 's' : ''} have low stock levels (&lt;10 units)</p>
                            </div>
                        ` : `
                            <div style="padding: 1rem; background: linear-gradient(135deg, #d1fae5 0%, #a7f3d0 100%); border-radius: 0.75rem; border-left: 4px solid var(--color-green-600); text-align: center;">
                                <i data-lucide="check-circle" style="width: 2rem; height: 2rem; color: var(--color-green-600); margin-bottom: 0.5rem;"></i>
                                <p style="font-weight: 600; color: var(--color-green-600); margin: 0; font-size: 0.875rem;">All systems operational</p>
                                <p style="color: #065f46; font-size: 0.75rem; margin-top: 0.25rem;">No active alerts</p>
                            </div>
                        `}
                        <div style="margin-top: 1rem; padding-top: 1rem; border-top: 1px solid var(--color-gray-200);">
                            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
                                <span style="font-size: 0.875rem; color: var(--color-gray-500);">Pending Orders</span>
                                <span style="font-weight: 700; color: #0f172a;">${(ordersData || []).filter(o => o.status === 'Pending').length}</span>
                            </div>
                            <div style="display: flex; justify-content: space-between; align-items: center;">
                                <span style="font-size: 0.875rem; color: var(--color-gray-500);">Open Support Tickets</span>
                                <span style="font-weight: 700; color: #0f172a;">${(supportTicketsData || []).filter(t => t.status === 'Open' || t.status === 'In Progress').length}</span>
                            </div>
                        </div>
                    </div>
                </div>
                <!-- Top Products Table -->
                <div class="kpi-card p-6 mt-6">
                    <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 1.5rem;">
                        <h3 class="text-xl font-semibold" style="color: #0f172a; margin: 0;">Top Products (Last 30 Days)</h3>
                        <i data-lucide="award" style="width: 1.5rem; height: 1.5rem; color: var(--color-yellow-600);"></i>
                    </div>
                    <div class="table-container">
                        <table class="data-table">
                            <thead>
                                <tr>
                                    <th>Rank</th>
                                    <th>Product</th>
                                    <th>Category</th>
                                    <th>Units Sold</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${topProducts.length > 0 ? topProducts.map((p, idx) => `
                                    <tr>
                                        <td style="font-weight: 700; color: ${idx === 0 ? 'var(--color-yellow-600)' : idx === 1 ? 'var(--color-gray-500)' : idx === 2 ? '#cd7f32' : 'var(--color-gray-400)'};">#${idx + 1}</td>
                                        <td style="color: #0f172a; font-weight: 600;">${p.name}</td>
                                        <td style="color: var(--color-gray-500);">${p.category || 'N/A'}</td>
                                        <td style="color: var(--color-green-600); font-weight: 600;">${p.sold}</td>
                                    </tr>
                                `).join('') : `<tr><td colspan="4" style="text-align: center; color: var(--color-gray-500); padding: 2rem;">No sales data recorded this month.</td></tr>`}
                            </tbody>
                        </table>
                    </div>
                </div>
            `;
            lucide.createIcons();
        }

        // 1. Product & Storefront Management
        function renderProductModule(submodule) {
            setPageTitle('Product & Storefront Management');
            const content = document.getElementById('content-container');
            let moduleTitle = 'Product & Storefront Management';
            let submoduleContent = '';

            const getProductStatusBadge = (stock) => {
                if (stock >= 50) return 'active';
                if (stock >= 10 && stock < 50) return 'low-stock';
                if (stock < 10) return 'critical-stock';
                return 'inactive';
            };
            
            const productRows = productsData.map((p, index) => {
                const statusClass = p.status === 'Active' ? 'active' : (p.status === 'Low Stock' ? 'low-stock' : (p.status === 'Critical Stock' ? 'critical-stock' : 'inactive'));
                return `
                <tr style="transition: all 0.2s; border-bottom: 1px solid #f3f4f6;" 
                    onmouseover="this.style.backgroundColor='#f9fafb'; this.style.transform='scale(1.01)';" 
                    onmouseout="this.style.backgroundColor='transparent'; this.style.transform='scale(1)';">
                    <td style="padding: 1rem 1.5rem; color: #6b7280; font-weight: 600; font-size: 0.875rem;">#${p.id}</td>
                    <td style="padding: 1rem 1.5rem;">
                        <div style="color: #1f2937; font-weight: 600; font-size: 0.9375rem; margin-bottom: 0.25rem;">${p.name}</div>
                        ${p.description ? `<div style="color: #6b7280; font-size: 0.8125rem; line-height: 1.4; max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${p.description.substring(0, 60)}${p.description.length > 60 ? '...' : ''}</div>` : ''}
                    </td>
                    <td style="padding: 1rem 1.5rem;">
                        <span style="color: #059669; font-weight: 700; font-size: 1rem;">${formatCurrency(parseFloat(p.price))}</span>
                    </td>
                    <td style="padding: 1rem 1.5rem;">
                        <span class="status-badge ${getProductStatusBadge(parseInt(p.stock))}" style="font-weight: 600; padding: 0.375rem 0.75rem; border-radius: 0.375rem; font-size: 0.8125rem;">${p.stock} units</span>
                    </td>
                    <td style="padding: 1rem 1.5rem;">
                        <span style="display: inline-flex; align-items: center; gap: 0.375rem; background: #e0e7ff; color: #4f46e5; padding: 0.375rem 0.75rem; border-radius: 0.375rem; font-size: 0.8125rem; font-weight: 500;">
                            <i data-lucide="tag" style="width: 0.75rem; height: 0.75rem;"></i>
                            ${p.category || 'N/A'}
                        </span>
                    </td>
                    <td style="padding: 1rem 1.5rem;">
                        <span class="status-badge ${statusClass}" style="font-weight: 600; padding: 0.375rem 0.75rem; border-radius: 0.375rem; font-size: 0.8125rem; text-transform: capitalize;">${p.status}</span>
                    </td>
                    <td style="padding: 1rem 1.5rem; width: 200px;">
                        <div style="display: flex; gap: 0.5rem; align-items: center; justify-content: center;">
                            <button class="btn-base" 
                                onclick="showProductForm(${p.id})" 
                                title="Edit Product"
                                style="padding: 0.5rem 0.875rem; font-size: 0.8125rem; background: #eff6ff; color: #2563eb; border: 1px solid #bfdbfe; border-radius: 0.5rem; font-weight: 500; display: flex; align-items: center; gap: 0.375rem; transition: all 0.2s; cursor: pointer;"
                                onmouseover="this.style.background='#dbeafe'; this.style.borderColor='#93c5fd'; this.style.transform='translateY(-1px)'"
                                onmouseout="this.style.background='#eff6ff'; this.style.borderColor='#bfdbfe'; this.style.transform='translateY(0)'">
                                <i data-lucide="edit-2" style="width: 0.875rem; height: 0.875rem;"></i>
                                <span>Edit</span>
                            </button>
                            <button class="btn-base"
                                onclick="deleteProduct(${p.id}, '${p.name.replace(/'/g, "\\'")}')" 
                                title="Delete Product"
                                style="padding: 0.5rem 0.875rem; font-size: 0.8125rem; background: #fef2f2; color: #dc2626; border: 1px solid #fecaca; border-radius: 0.5rem; font-weight: 500; display: flex; align-items: center; gap: 0.375rem; transition: all 0.2s; cursor: pointer;"
                                onmouseover="this.style.background='#fee2e2'; this.style.borderColor='#fca5a5'; this.style.transform='translateY(-1px)'"
                                onmouseout="this.style.background='#fef2f2'; this.style.borderColor='#fecaca'; this.style.transform='translateY(0)'">
                                <i data-lucide="trash-2" style="width: 0.875rem; height: 0.875rem;"></i>
                                <span>Delete</span>
                            </button>
                        </div>
                    </td>
                </tr>
            `;
            }).join('');


            switch (submodule) {
                case 'products':
                    moduleTitle = 'Product List (Inventory & Pricing)';
                    submoduleContent = `
                        <div class="mb-6">
                            <!-- Header Section -->
                            <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); border-radius: 0.75rem; padding: 2rem; margin-bottom: 1.5rem; color: white;">
                                <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 1rem;">
                                    <div>
                                        <h2 style="font-size: 1.5rem; font-weight: 700; margin-bottom: 0.5rem; color: white;">Product Management</h2>
                                        <p style="opacity: 0.9; font-size: 0.9375rem; margin: 0;">Manage your product inventory. Add, edit, or delete products easily.</p>
                                    </div>
                                    <div style="display: flex; gap: 0.75rem; flex-wrap: wrap;">
                                        ${productsData.length > 0 ? `
                                        <button class="btn-base" onclick="clearAllProducts()" 
                                            style="background: rgba(255, 255, 255, 0.2); color: white; border: 1px solid rgba(255, 255, 255, 0.3); padding: 0.625rem 1.25rem; font-weight: 500; transition: all 0.2s;"
                                            onmouseover="this.style.background='rgba(255, 255, 255, 0.3)'" 
                                            onmouseout="this.style.background='rgba(255, 255, 255, 0.2)'">
                                            <i data-lucide="trash-2" style="width: 1rem; height: 1rem; margin-right: 0.5rem;"></i>
                                            Clear All
                                        </button>
                                        ` : ''}
                                        <button class="btn-base" onclick="showProductForm()" 
                                            style="background: white; color: #667eea; padding: 0.625rem 1.25rem; font-weight: 600; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1); transition: all 0.2s;"
                                            onmouseover="this.style.transform='translateY(-2px)'; this.style.boxShadow='0 6px 12px -1px rgba(0, 0, 0, 0.15)'" 
                                            onmouseout="this.style.transform='translateY(0)'; this.style.boxShadow='0 4px 6px -1px rgba(0, 0, 0, 0.1)'">
                                            <i data-lucide="plus" style="width: 1rem; height: 1rem; margin-right: 0.5rem;"></i>
                                            Add New Product
                                        </button>
                                    </div>
                                </div>
                            </div>
                            
                            ${productsData.length === 0 ? `
                            <div class="kpi-card p-8 mb-4" style="background: linear-gradient(135deg, #f0f9ff 0%, #e0e7ff 100%); border: 2px dashed #c7d2fe; text-align: center; border-radius: 1rem;">
                                <div style="width: 80px; height: 80px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); border-radius: 50%; display: flex; align-items: center; justify-content: center; margin: 0 auto 1.5rem;">
                                    <i data-lucide="package" style="width: 2.5rem; height: 2.5rem; color: white;"></i>
                                </div>
                                <h3 style="font-size: 1.5rem; font-weight: 700; color: #1f2937; margin-bottom: 0.75rem;">No Products Yet</h3>
                                <p style="color: #6b7280; font-size: 1rem; margin-bottom: 2rem; max-width: 500px; margin-left: auto; margin-right: auto;">Start building your inventory by adding your first product. You can manage all your products from here.</p>
                                <button class="btn-base" onclick="showProductForm()" 
                                    style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; font-weight: 600; padding: 0.875rem 2rem; border-radius: 0.5rem; box-shadow: 0 4px 6px -1px rgba(102, 126, 234, 0.4); transition: all 0.2s;"
                                    onmouseover="this.style.transform='translateY(-2px)'; this.style.boxShadow='0 6px 12px -1px rgba(102, 126, 234, 0.5)'" 
                                    onmouseout="this.style.transform='translateY(0)'; this.style.boxShadow='0 4px 6px -1px rgba(102, 126, 234, 0.4)'">
                                    <i data-lucide="plus" style="width: 1.125rem; height: 1.125rem; margin-right: 0.5rem;"></i>
                                    Add Your First Product
                                </button>
                            </div>
                            ` : ''}
                        </div>
                        
                        <!-- Products Table Card -->
                        <div class="kpi-card" style="padding: 0; overflow: hidden; border-radius: 0.75rem; box-shadow: 0 1px 3px 0 rgba(0, 0, 0, 0.1), 0 1px 2px 0 rgba(0, 0, 0, 0.06);">
                            <div style="background: #f9fafb; padding: 1.25rem 1.5rem; border-bottom: 1px solid #e5e7eb; display: flex; justify-content: space-between; align-items: center;">
                                <div>
                                    <h3 style="font-size: 1.125rem; font-weight: 700; color: #1f2937; margin: 0;">Product Inventory</h3>
                                    <p style="font-size: 0.875rem; color: #6b7280; margin: 0.25rem 0 0 0;">${productsData.length} ${productsData.length === 1 ? 'product' : 'products'} in your inventory</p>
                                </div>
                                <div style="display: flex; align-items: center; gap: 0.5rem; background: white; padding: 0.5rem 0.75rem; border-radius: 0.5rem; border: 1px solid #e5e7eb;">
                                    <i data-lucide="package" style="width: 1rem; height: 1rem; color: #667eea;"></i>
                                    <span style="font-weight: 600; color: #1f2937; font-size: 0.875rem;">${productsData.length}</span>
                                </div>
                            </div>
                            <div class="table-container" style="overflow-x: auto;">
                                <table class="data-table" style="margin: 0;">
                                    <thead>
                                        <tr style="background: #f9fafb;">
                                            <th style="padding: 1rem 1.5rem; font-weight: 600; color: #374151; font-size: 0.875rem; text-transform: uppercase; letter-spacing: 0.05em; border-bottom: 2px solid #e5e7eb;">ID</th>
                                            <th style="padding: 1rem 1.5rem; font-weight: 600; color: #374151; font-size: 0.875rem; text-transform: uppercase; letter-spacing: 0.05em; border-bottom: 2px solid #e5e7eb;">Product Name</th>
                                            <th style="padding: 1rem 1.5rem; font-weight: 600; color: #374151; font-size: 0.875rem; text-transform: uppercase; letter-spacing: 0.05em; border-bottom: 2px solid #e5e7eb;">Price</th>
                                            <th style="padding: 1rem 1.5rem; font-weight: 600; color: #374151; font-size: 0.875rem; text-transform: uppercase; letter-spacing: 0.05em; border-bottom: 2px solid #e5e7eb;">Stock</th>
                                            <th style="padding: 1rem 1.5rem; font-weight: 600; color: #374151; font-size: 0.875rem; text-transform: uppercase; letter-spacing: 0.05em; border-bottom: 2px solid #e5e7eb;">Category</th>
                                            <th style="padding: 1rem 1.5rem; font-weight: 600; color: #374151; font-size: 0.875rem; text-transform: uppercase; letter-spacing: 0.05em; border-bottom: 2px solid #e5e7eb;">Status</th>
                                            <th style="padding: 1rem 1.5rem; font-weight: 600; color: #374151; font-size: 0.875rem; text-transform: uppercase; letter-spacing: 0.05em; border-bottom: 2px solid #e5e7eb; text-align: center;">Actions</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        ${productsData.length > 0 ? productRows : `
                                        <tr>
                                            <td colspan="7" style="text-align: center; padding: 3rem; color: #9ca3af;">
                                                <i data-lucide="package-x" style="width: 3rem; height: 3rem; margin: 0 auto 1rem; display: block; opacity: 0.5;"></i>
                                                <p style="font-size: 1rem; font-weight: 500; margin-bottom: 0.5rem;">No products found</p>
                                                <p style="font-size: 0.875rem;">Click "Add New Product" to create your first product.</p>
                                            </td>
                                        </tr>
                                        `}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    `;
                    break;
                case 'categories':
                    moduleTitle = 'Category Management';
                    const categoryRows = categoriesData.map(cat => `
                        <tr>
                            <td>${cat.id}</td>
                            <td style="color: #1f2937; font-weight: 500;">${cat.name}</td>
                            <td>${cat.description || 'N/A'}</td>
                            <td><span class="status-badge ${cat.status === 'Active' ? 'active' : 'inactive'}">${cat.status}</span></td>
                            <td style="width: 150px;">
                                <button class="btn-base" style="padding: 0.25rem 0.5rem; margin-right: 0.5rem; background-color: var(--color-light-grey);" 
                                    onclick="showCategoryForm(${cat.id})">
                                    <i data-lucide="edit" style="width: 1rem; height: 1rem;"></i>
                                </button>
                                <button class="btn-base" style="padding: 0.25rem 0.5rem; background-color: var(--color-red-600); color: white;"
                                    onclick="deleteCategory(${cat.id}, '${cat.name}')">
                                    <i data-lucide="trash-2" style="width: 1rem; height: 1rem;"></i>
                                </button>
                            </td>
                        </tr>
                    `).join('');
                    
                    submoduleContent = `
                        <div class="mb-6 flex justify-between items-center">
                            <p class="text-gray-500">Create and manage product categories.</p>
                            <button class="btn-base btn-primary text-sm" onclick="showCategoryForm()">
                                <i data-lucide="plus" style="width: 1rem; height: 1rem; margin-right: 0.5rem;"></i>
                                Add New Category
                            </button>
                        </div>
                        <div class="kpi-card p-6">
                            <h3 class="text-xl font-semibold mb-4">Category List (${categoriesData.length} Categories)</h3>
                            <div class="table-container" style="overflow-x: auto;">
                                <table class="data-table">
                                    <thead>
                                        <tr>
                                            <th>ID</th>
                                            <th>Name</th>
                                            <th>Description</th>
                                            <th>Status</th>
                                            <th>Actions</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        ${categoriesData.length > 0 ? categoryRows : `<tr><td colspan="5" class="text-center text-gray-500 py-4">No categories found. Click "Add New Category" to create one.</td></tr>`}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    `;
                    break;
                case 'storefront':
                    moduleTitle = 'Storefront Preview';
                    const activeProducts = productsData.filter(p => p.status === 'Active').slice(0, 6);
                    const productCards = activeProducts.map(p => `
                        <div style="border: 1px solid #e5e7eb; border-radius: 0.75rem; overflow: hidden; background: white; transition: transform 0.2s, box-shadow 0.2s;" 
                             onmouseover="this.style.transform='translateY(-4px)'; this.style.boxShadow='0 10px 15px -3px rgba(0,0,0,0.1)'"
                             onmouseout="this.style.transform='translateY(0)'; this.style.boxShadow='none'">
                            <div style="width: 100%; height: 200px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); display: flex; align-items: center; justify-content: center; color: white; font-size: 2rem; font-weight: bold;">
                                ${p.name.charAt(0)}
                            </div>
                            <div style="padding: 1rem;">
                                <h4 style="font-weight: 600; color: #1f2937; margin-bottom: 0.5rem; font-size: 1rem;">${p.name}</h4>
                                <p style="font-size: 0.875rem; color: #6b7280; margin-bottom: 0.75rem; display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; overflow: hidden;">${p.description || 'No description'}</p>
                                <div style="display: flex; justify-content: space-between; align-items: center;">
                                    <span style="font-size: 1.25rem; font-weight: 700; color: #1f2937;">${formatCurrency(parseFloat(p.price))}</span>
                                    <span class="status-badge ${p.stock < 10 ? 'low-stock' : 'active'}" style="font-size: 0.75rem;">Stock: ${p.stock}</span>
                                </div>
                            </div>
                        </div>
                    `).join('');
                    
                    submoduleContent = `
                        <p class="mb-6 text-gray-500">Preview how products appear to customers on the storefront.</p>
                        <div class="kpi-card p-6">
                            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.5rem;">
                                <h3 class="text-xl font-semibold">Storefront Preview</h3>
                                <div style="display: flex; gap: 0.5rem;">
                                    <button class="btn-base btn-secondary" style="padding: 0.5rem 1rem; font-size: 0.875rem;">
                                        <i data-lucide="monitor" style="width: 1rem; height: 1rem; margin-right: 0.5rem;"></i>
                                        Desktop
                                    </button>
                                    <button class="btn-base btn-secondary" style="padding: 0.5rem 1rem; font-size: 0.875rem;">
                                        <i data-lucide="smartphone" style="width: 1rem; height: 1rem; margin-right: 0.5rem;"></i>
                                        Mobile
                                    </button>
                                </div>
                            </div>
                            <div style="border: 2px solid #e5e7eb; border-radius: 0.75rem; overflow: hidden; background-color: #f9fafb;">
                                <div style="background: linear-gradient(135deg, var(--color-primary-dark) 0%, var(--color-dark-grey) 100%); color: white; padding: 1rem; display: flex; justify-content: space-between; align-items: center;">
                                    <div>
                                        <h4 style="font-size: 1.25rem; font-weight: 700; margin: 0;">iMARKET Store</h4>
                                        <p style="font-size: 0.875rem; margin: 0.25rem 0 0 0; opacity: 0.9;">Your one-stop shop</p>
                                    </div>
                                    <div style="display: flex; gap: 1rem; align-items: center;">
                                        <i data-lucide="search" style="width: 1.25rem; height: 1.25rem; opacity: 0.9;"></i>
                                        <i data-lucide="shopping-cart" style="width: 1.25rem; height: 1.25rem; opacity: 0.9;"></i>
                                    </div>
                                </div>
                                <div style="padding: 1.5rem;">
                                    <div style="margin-bottom: 1.5rem;">
                                        <h5 style="font-size: 1.125rem; font-weight: 600; color: #1f2937; margin-bottom: 1rem;">Featured Products</h5>
                                        <div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(250px, 1fr)); gap: 1.5rem;">
                                            ${productCards}
                                        </div>
                                    </div>
                                    <div style="text-align: center; padding: 2rem; background: #f3f4f6; border-radius: 0.5rem;">
                                        <p style="color: #6b7280; margin: 0;">Showing ${activeProducts.length} of ${productsData.filter(p => p.status === 'Active').length} active products</p>
                                    </div>
                                </div>
                            </div>
                        </div>
                    `;
                    break;
            }

            content.innerHTML = `<h2 class="page-header">${moduleTitle}</h2>${submoduleContent}`;
            lucide.createIcons();
        }

        // 2. Order & Checkout Management
        function renderOrderModule(submodule) {
            setPageTitle('Order & Checkout Management');
            const content = document.getElementById('content-container');
            let moduleTitle = 'Order & Checkout Management';
            let submoduleContent = '';

            const getOrderStatusBadge = (status) => {
                // Ensure statuses match CSS classes
                return status.toLowerCase().replace(' ', '-');
            };

            const orderRows = ordersData.map((o, index) => `
                <tr class="order-row" data-order-id="${o.id}" data-customer="${o.customer.toLowerCase()}" data-status="${o.status.toLowerCase()}" data-amount="${o.total}">
                    <td><input type="checkbox" class="order-checkbox" value="${o.id}" onchange="updateSelectedCount()"></td>
                    <td style="color: #1f2937; font-weight: 500;">#${o.id}</td>
                    <td>${o.customer}</td>
                    <td>${formatCurrency(o.total)}</td>
                    <td>${o.date || new Date().toLocaleDateString()}</td>
                    <td><span class="status-badge ${getOrderStatusBadge(o.status)}">${o.status}</span></td>
                    <td style="width: 200px;">
                        <div style="display: flex; gap: 0.5rem; align-items: center;">
                            <button onclick="viewOrderDetails(${o.id})" class="btn-base btn-secondary" style="padding: 0.35rem 0.75rem; font-size: 0.75rem;">
                                <i data-lucide="eye" style="width: 0.875rem; height: 0.875rem; margin-right: 0.25rem;"></i>
                                View
                            </button>
                            <select onchange="showCustomActionModal('Confirm Status Change', 'Change status for order **#${o.id}** to **' + this.value + '**?', 'Confirm', () => updateOrderStatus(${o.id}, this.value))" 
                                class="form-group" style="padding: 0.35rem 0.5rem; font-size: 0.75rem; border-radius: 0.3rem; flex: 1;">
                                <option value="${o.status}" selected disabled>${o.status}</option>
                                <option value="Pending">Pending</option>
                                <option value="Processing">Processing</option>
                                <option value="Shipped">Shipped</option>
                                <option value="Delivered">Delivered</option>
                                <option value="Cancelled">Cancelled</option>
                            </select>
                        </div>
                    </td>
                </tr>
            `).join('');

            switch (submodule) {
                case 'orders':
                    moduleTitle = 'View All Orders & Status Management';
                    submoduleContent = `
                        <div class="mb-6">
                            <p class="text-gray-500 mb-4">View all orders and manage their status. Search, filter, and export orders.</p>
                            
                            <!-- Search and Filter Controls -->
                            <div class="kpi-card p-4 mb-4" style="background: #f9fafb;">
                                <div style="display: grid; grid-template-columns: 2fr 1fr 1fr auto; gap: 1rem; align-items: end;">
                                    <div>
                                        <label style="display: block; font-size: 0.875rem; font-weight: 600; color: #374151; margin-bottom: 0.5rem;">Search Orders</label>
                                        <input type="text" id="order-search" placeholder="Search by Order ID, Customer, or Amount..." 
                                            style="width: 100%; padding: 0.75rem; border: 1px solid #d1d5db; border-radius: 0.5rem; font-size: 0.875rem;"
                                            onkeyup="filterOrders()">
                                    </div>
                                    <div>
                                        <label style="display: block; font-size: 0.875rem; font-weight: 600; color: #374151; margin-bottom: 0.5rem;">Filter by Status</label>
                                        <select id="status-filter" onchange="filterOrders()" 
                                            style="width: 100%; padding: 0.75rem; border: 1px solid #d1d5db; border-radius: 0.5rem; font-size: 0.875rem;">
                                            <option value="">All Statuses</option>
                                            <option value="Pending">Pending</option>
                                            <option value="Processing">Processing</option>
                                            <option value="Shipped">Shipped</option>
                                            <option value="Delivered">Delivered</option>
                                            <option value="Cancelled">Cancelled</option>
                                        </select>
                                    </div>
                                    <div>
                                        <label style="display: block; font-size: 0.875rem; font-weight: 600; color: #374151; margin-bottom: 0.5rem;">Sort By</label>
                                        <select id="sort-orders" onchange="filterOrders()" 
                                            style="width: 100%; padding: 0.75rem; border: 1px solid #d1d5db; border-radius: 0.5rem; font-size: 0.875rem;">
                                            <option value="id-desc">Newest First</option>
                                            <option value="id-asc">Oldest First</option>
                                            <option value="amount-desc">Highest Amount</option>
                                            <option value="amount-asc">Lowest Amount</option>
                                            <option value="customer-asc">Customer A-Z</option>
                                        </select>
                                    </div>
                                    <div style="display: flex; gap: 0.5rem;">
                                        <button onclick="exportOrders()" class="btn-base btn-secondary" style="padding: 0.75rem 1rem; font-size: 0.875rem; white-space: nowrap;">
                                            <i data-lucide="download" style="width: 1rem; height: 1rem; margin-right: 0.5rem;"></i>
                                            Export
                                        </button>
                                        <button onclick="printOrders()" class="btn-base btn-secondary" style="padding: 0.75rem 1rem; font-size: 0.875rem; white-space: nowrap;">
                                            <i data-lucide="printer" style="width: 1rem; height: 1rem; margin-right: 0.5rem;"></i>
                                            Print
                                        </button>
                                    </div>
                                </div>
                                
                                <!-- Bulk Actions -->
                                <div style="margin-top: 1rem; padding-top: 1rem; border-top: 1px solid #e5e7eb; display: flex; gap: 0.5rem; align-items: center;">
                                    <input type="checkbox" id="select-all-orders" onchange="toggleSelectAllOrders()" style="margin-right: 0.5rem;">
                                    <label for="select-all-orders" style="font-size: 0.875rem; color: #374151; margin-right: 1rem;">Select All</label>
                                    <select id="bulk-status-action" style="padding: 0.5rem; border: 1px solid #d1d5db; border-radius: 0.375rem; font-size: 0.875rem;">
                                        <option value="">Bulk Actions</option>
                                        <option value="Processing">Mark as Processing</option>
                                        <option value="Shipped">Mark as Shipped</option>
                                        <option value="Delivered">Mark as Delivered</option>
                                        <option value="Cancelled">Mark as Cancelled</option>
                                    </select>
                                    <button onclick="bulkUpdateOrderStatus()" class="btn-base btn-primary" style="padding: 0.5rem 1rem; font-size: 0.875rem;">
                                        Apply
                                    </button>
                                    <span id="selected-count" style="font-size: 0.875rem; color: #6b7280; margin-left: auto;"></span>
                                </div>
                            </div>
                        </div>
                        
                        <div class="kpi-card p-6">
                            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem;">
                                <h3 class="text-xl font-semibold" id="order-count-title">Order List (<span id="filtered-order-count">${ordersData.length}</span> Orders Found)</h3>
                            </div>
                            <div class="table-container" style="overflow-x: auto;">
                                <table class="data-table" id="orders-table">
                                    <thead>
                                        <tr>
                                            <th style="width: 40px;"><input type="checkbox" id="table-select-all" onchange="toggleSelectAllOrders()"></th>
                                            <th>Order ID</th>
                                            <th>Customer</th>
                                            <th>Total Amount</th>
                                            <th>Date</th>
                                            <th>Current Status</th>
                                            <th>Actions</th>
                                        </tr>
                                    </thead>
                                    <tbody id="orders-table-body">
                                        ${ordersData.length > 0 ? orderRows : `<tr><td colspan="7" class="text-center text-gray-500 py-4">No orders placed yet.</td></tr>`}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    `;
                    break;
                case 'payments':
                    moduleTitle = 'Payment Transaction Logs';
                    const transactionRows = transactionsData.map(t => {
                        const statusClass = t.status === 'Completed' ? 'active' : (t.status === 'Pending' ? 'pending' : (t.status === 'Failed' ? 'cancelled' : 'pending'));
                        return `
                        <tr>
                            <td>${t.transaction_number}</td>
                            <td>${t.order_number || 'N/A'}</td>
                            <td>${t.customer_name || 'N/A'}</td>
                            <td>${formatCurrency(parseFloat(t.amount))}</td>
                            <td>${t.payment_method}</td>
                            <td><span class="status-badge ${statusClass}">${t.status}</span></td>
                            <td>${new Date(t.transaction_date).toLocaleDateString()}</td>
                        </tr>
                    `;
                    }).join('');
                    
                    submoduleContent = `
                        <p class="mb-6 text-gray-500">Monitor all payment transactions and their status.</p>
                        <div class="kpi-card p-6">
                            <h3 class="text-xl font-semibold mb-4">Transaction Logs (${transactionsData.length} Transactions)</h3>
                            <div class="table-container" style="overflow-x: auto;">
                                <table class="data-table">
                                    <thead>
                                        <tr>
                                            <th>Transaction #</th>
                                            <th>Order #</th>
                                            <th>Customer</th>
                                            <th>Amount</th>
                                            <th>Payment Method</th>
                                            <th>Status</th>
                                            <th>Date</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        ${transactionsData.length > 0 ? transactionRows : `<tr><td colspan="7" class="text-center text-gray-500 py-4">No transactions found.</td></tr>`}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    `;
                    break;
            }

            content.innerHTML = `<h2 class="page-header">${moduleTitle}</h2>${submoduleContent}`;
            lucide.createIcons();
            
            // Store original orders data for filtering
            if (submodule === 'orders') {
                window.allOrdersData = ordersData;
                updateSelectedCount();
            }
        }

        // --- ORDER MANAGEMENT FUNCTIONS ---
        function updateOrderStatus(orderId, newStatus) {
            // This submits a functional PHP POST form to update the database
            const updateForm = document.createElement('form');
            updateForm.method = 'POST';
            updateForm.action = '<?php echo basename(__FILE__); ?>';
            updateForm.style.display = 'none';

            const actionInput = document.createElement('input');
            actionInput.type = 'hidden';
            actionInput.name = 'action';
            actionInput.value = 'update_order_status';
            updateForm.appendChild(actionInput);

            const idInput = document.createElement('input');
            idInput.type = 'hidden';
            idInput.name = 'id';
            idInput.value = orderId;
            updateForm.appendChild(idInput);

            const statusInput = document.createElement('input');
            statusInput.type = 'hidden';
            statusInput.name = 'status';
            statusInput.value = newStatus;
            updateForm.appendChild(statusInput);
            
            document.body.appendChild(updateForm);
            updateForm.submit();
        }
        
        function filterOrders() {
            const searchTerm = document.getElementById('order-search')?.value.toLowerCase() || '';
            const statusFilter = document.getElementById('status-filter')?.value.toLowerCase() || '';
            const sortBy = document.getElementById('sort-orders')?.value || 'id-desc';
            const tbody = document.getElementById('orders-table-body');
            const countSpan = document.getElementById('filtered-order-count');
            
            if (!tbody) return;
            
            let filtered = window.allOrdersData || ordersData;
            
            // Apply search filter
            if (searchTerm) {
                filtered = filtered.filter(o => 
                    o.id.toString().includes(searchTerm) ||
                    o.customer.toLowerCase().includes(searchTerm) ||
                    o.total.toString().includes(searchTerm)
                );
            }
            
            // Apply status filter
            if (statusFilter) {
                filtered = filtered.filter(o => o.status.toLowerCase() === statusFilter);
            }
            
            // Apply sorting
            filtered.sort((a, b) => {
                switch(sortBy) {
                    case 'id-desc': return b.id - a.id;
                    case 'id-asc': return a.id - b.id;
                    case 'amount-desc': return b.total - a.total;
                    case 'amount-asc': return a.total - b.total;
                    case 'customer-asc': return a.customer.localeCompare(b.customer);
                    default: return b.id - a.id;
                }
            });
            
            // Update table
            const getOrderStatusBadge = (status) => status.toLowerCase().replace(' ', '-');
            const rows = filtered.map(o => `
                <tr class="order-row" data-order-id="${o.id}" data-customer="${o.customer.toLowerCase()}" data-status="${o.status.toLowerCase()}" data-amount="${o.total}">
                    <td><input type="checkbox" class="order-checkbox" value="${o.id}" onchange="updateSelectedCount()"></td>
                    <td style="color: #1f2937; font-weight: 500;">#${o.id}</td>
                    <td>${o.customer}</td>
                    <td>${formatCurrency(o.total)}</td>
                    <td>${o.date || new Date().toLocaleDateString()}</td>
                    <td><span class="status-badge ${getOrderStatusBadge(o.status)}">${o.status}</span></td>
                    <td style="width: 200px;">
                        <div style="display: flex; gap: 0.5rem; align-items: center;">
                            <button onclick="viewOrderDetails(${o.id})" class="btn-base btn-secondary" style="padding: 0.35rem 0.75rem; font-size: 0.75rem;">
                                <i data-lucide="eye" style="width: 0.875rem; height: 0.875rem; margin-right: 0.25rem;"></i>
                                View
                            </button>
                            <select onchange="showCustomActionModal('Confirm Status Change', 'Change status for order **#${o.id}** to **' + this.value + '**?', 'Confirm', () => updateOrderStatus(${o.id}, this.value))" 
                                class="form-group" style="padding: 0.35rem 0.5rem; font-size: 0.75rem; border-radius: 0.3rem; flex: 1;">
                                <option value="${o.status}" selected disabled>${o.status}</option>
                                <option value="Pending">Pending</option>
                                <option value="Processing">Processing</option>
                                <option value="Shipped">Shipped</option>
                                <option value="Delivered">Delivered</option>
                                <option value="Cancelled">Cancelled</option>
                            </select>
                        </div>
                    </td>
                </tr>
            `).join('');
            
            tbody.innerHTML = filtered.length > 0 ? rows : `<tr><td colspan="7" class="text-center text-gray-500 py-4">No orders found matching your criteria.</td></tr>`;
            if (countSpan) countSpan.textContent = filtered.length;
            
            lucide.createIcons();
            updateSelectedCount();
        }
        
        function viewOrderDetails(orderId) {
            const order = (window.allOrdersData || ordersData).find(o => o.id == orderId);
            if (!order) {
                showCustomActionModal('Error', 'Order not found.', 'OK');
                return;
            }
            
            const detailsHTML = `
                <div style="padding: 1.5rem;">
                    <h3 style="font-size: 1.25rem; font-weight: 700; color: #1f2937; margin-bottom: 1.5rem;">Order Details #${order.id}</h3>
                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; margin-bottom: 1.5rem;">
                        <div>
                            <p style="font-size: 0.875rem; color: #6b7280; margin-bottom: 0.25rem;">Customer</p>
                            <p style="font-weight: 600; color: #1f2937;">${order.customer}</p>
                        </div>
                        <div>
                            <p style="font-size: 0.875rem; color: #6b7280; margin-bottom: 0.25rem;">Order Date</p>
                            <p style="font-weight: 600; color: #1f2937;">${order.date || new Date().toLocaleDateString()}</p>
                        </div>
                        <div>
                            <p style="font-size: 0.875rem; color: #6b7280; margin-bottom: 0.25rem;">Status</p>
                            <p><span class="status-badge ${order.status.toLowerCase().replace(' ', '-')}">${order.status}</span></p>
                        </div>
                        <div>
                            <p style="font-size: 0.875rem; color: #6b7280; margin-bottom: 0.25rem;">Total Amount</p>
                            <p style="font-weight: 700; color: #059669; font-size: 1.125rem;">${formatCurrency(order.total)}</p>
                        </div>
                    </div>
                    <div style="border-top: 1px solid #e5e7eb; padding-top: 1rem; margin-top: 1rem;">
                        <p style="font-size: 0.875rem; color: #6b7280; margin-bottom: 0.5rem;">Order Items</p>
                        <p style="color: #1f2937;">Product details and items will be displayed here.</p>
                    </div>
                </div>
            `;
            
            const modalContainer = document.getElementById('modal-container');
            modalContainer.innerHTML = detailsHTML;
            document.getElementById('custom-modal-backdrop').classList.remove('hidden');
            lucide.createIcons();
        }
        
        function exportOrders() {
            const searchTerm = document.getElementById('order-search')?.value.toLowerCase() || '';
            const statusFilter = document.getElementById('status-filter')?.value.toLowerCase() || '';
            let filtered = window.allOrdersData || ordersData;
            
            if (searchTerm) {
                filtered = filtered.filter(o => 
                    o.id.toString().includes(searchTerm) ||
                    o.customer.toLowerCase().includes(searchTerm) ||
                    o.total.toString().includes(searchTerm)
                );
            }
            if (statusFilter) {
                filtered = filtered.filter(o => o.status.toLowerCase() === statusFilter);
            }
            
            // Create CSV content
            const headers = ['Order ID', 'Customer', 'Total Amount', 'Status', 'Date'];
            const rows = filtered.map(o => [
                o.id,
                o.customer,
                o.total,
                o.status,
                o.date || new Date().toLocaleDateString()
            ]);
            
            const csvContent = [
                headers.join(','),
                ...rows.map(row => row.map(cell => `"${cell}"`).join(','))
            ].join('\\n');
            
            // Download CSV
            const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
            const link = document.createElement('a');
            const url = URL.createObjectURL(blob);
            link.setAttribute('href', url);
            link.setAttribute('download', `orders_export_${new Date().toISOString().split('T')[0]}.csv`);
            link.style.visibility = 'hidden';
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
        }
        
        function printOrders() {
            const printWindow = window.open('', '_blank');
            const searchTerm = document.getElementById('order-search')?.value.toLowerCase() || '';
            const statusFilter = document.getElementById('status-filter')?.value.toLowerCase() || '';
            let filtered = window.allOrdersData || ordersData;
            
            if (searchTerm) {
                filtered = filtered.filter(o => 
                    o.id.toString().includes(searchTerm) ||
                    o.customer.toLowerCase().includes(searchTerm) ||
                    o.total.toString().includes(searchTerm)
                );
            }
            if (statusFilter) {
                filtered = filtered.filter(o => o.status.toLowerCase() === statusFilter);
            }
            
            const printContent = `
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Orders Report</title>
                    <style>
                        body { font-family: Arial, sans-serif; padding: 20px; }
                        h1 { color: #1f2937; }
                        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
                        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                        th { background-color: #f3f4f6; font-weight: 600; }
                    </style>
                </head>
                <body>
                    <h1>Orders Report</h1>
                    <p>Generated: ${new Date().toLocaleString()}</p>
                    <table>
                        <thead>
                            <tr>
                                <th>Order ID</th>
                                <th>Customer</th>
                                <th>Total Amount</th>
                                <th>Status</th>
                                <th>Date</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${filtered.map(o => `
                                <tr>
                                    <td>#${o.id}</td>
                                    <td>${o.customer}</td>
                                    <td>${formatCurrency(o.total)}</td>
                                    <td>${o.status}</td>
                                    <td>${o.date || new Date().toLocaleDateString()}</td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                </body>
                </html>
            `;
            
            printWindow.document.write(printContent);
            printWindow.document.close();
            printWindow.print();
        }
        
        function toggleSelectAllOrders() {
            const selectAll = document.getElementById('select-all-orders') || document.getElementById('table-select-all');
            const checkboxes = document.querySelectorAll('.order-checkbox');
            checkboxes.forEach(cb => cb.checked = selectAll?.checked || false);
            updateSelectedCount();
        }
        
        function updateSelectedCount() {
            const checked = document.querySelectorAll('.order-checkbox:checked');
            const countSpan = document.getElementById('selected-count');
            if (countSpan) {
                countSpan.textContent = checked.length > 0 ? `${checked.length} selected` : '';
            }
        }
        
        function bulkUpdateOrderStatus() {
            const selected = Array.from(document.querySelectorAll('.order-checkbox:checked')).map(cb => cb.value);
            const newStatus = document.getElementById('bulk-status-action')?.value;
            
            if (selected.length === 0) {
                showCustomActionModal('No Selection', 'Please select at least one order.', 'OK');
                return;
            }
            
            if (!newStatus) {
                showCustomActionModal('No Action', 'Please select a status to apply.', 'OK');
                return;
            }
            
            showCustomActionModal(
                'Confirm Bulk Update',
                `Update ${selected.length} order(s) to status "${newStatus}"?`,
                'Confirm',
                () => {
                    selected.forEach(orderId => {
                        updateOrderStatus(parseInt(orderId), newStatus);
                    });
                }
            );
        }

        // 3. Shipping & Address Management
        function renderShippingModule(submodule) {
            setPageTitle('Shipping & Address Management');
            const content = document.getElementById('content-container');
            let moduleTitle = 'Shipping & Address Management';
            let submoduleContent = '';

            switch (submodule) {
                case 'addresses':
                    moduleTitle = 'Customer Addresses & Validation';
                    submoduleContent = `
                        <div class="mb-6 flex justify-between items-center">
                            <p class="text-gray-500">View customer shipping addresses. Data pulled from the **customer_addresses** table.</p>
                            <button class="btn-base btn-primary text-sm" 
                                onclick="showCustomActionModal('Address Management', 'Address management functions (Add/Edit) are enabled. The list below uses live database data.', 'OK')">
                                <i data-lucide="plus" style="width: 1rem; height: 1rem; margin-right: 0.5rem;"></i>
                                Add New Address (Mock)
                            </button>
                        </div>
                        <div class="kpi-card p-6">
                            <h3 class="text-xl font-semibold mb-4">Customer Addresses List (${mockAddresses.length} Addresses)</h3>
                            <ul class="space-y-3" style="max-height: 500px; overflow-y: auto; padding-right: 10px;">
                                ${mockAddresses.map(a => `
                                    <li class="p-4 rounded-lg shadow-sm" style="background-color: ${a.status === 'Verified' ? '#f0fdf4' : (a.status === 'Requires Review' ? '#fffbe6' : '#fef2f2')}; border: 1px solid ${a.status === 'Verified' ? '#34d399' : (a.status === 'Requires Review' ? '#f59e0b' : '#f87171')};">
                                        <div class="flex justify-between items-start">
                                            <div>
                                                <p class="font-medium text-gray-900">(${a.id}) ${a.customer}</p>
                                                <p class="text-sm text-gray-600">${a.address}</p>
                                                <div class="mt-2">
                                                    <span class="status-badge ${getOrderStatusBadge(a.status).replace(' ', '-')}">${a.status}</span>
                                                </div>
                                            </div>
                                            <div class="flex space-x-2">
                                                <button style="color: #2563eb;" class="text-sm font-medium" 
                                                    onclick="showCustomActionModal('Edit Address', 'Editing address **${a.id}** for **${a.customer}** (Simulation).', 'Edit')">Edit</button>
                                                <button style="color: var(--color-red-600);" class="text-sm font-medium" 
                                                    onclick="showCustomActionModal('Remove Address', 'Are you sure you want to permanently remove this address for **${a.customer}** (ID: ${a.id})?', 'Delete', () => console.log('Remove Address ${a.id}'))">Remove</button>
                                            </div>
                                        </div>
                                    </li>
                                `).join('')}
                            </ul>
                            <p class="mt-4 text-sm text-gray-500">Total Addresses Found: ${mockAddresses.length}. Address data is loaded from the database.</p>
                        </div>
                    `;
                    break;
                case 'tracking':
                    moduleTitle = 'Shipment Tracking';
                    const shipmentRows = shipmentsData.map(s => {
                        const statusClass = s.status === 'Delivered' ? 'delivered' : (s.status === 'Out for Delivery' ? 'out-for-delivery' : (s.status === 'In Transit' ? 'in-transit' : 'processing'));
                        return `
                        <tr>
                            <td>${s.tracking_number}</td>
                            <td>${s.order_number || 'N/A'}</td>
                            <td>${s.customer_name || 'N/A'}</td>
                            <td>${s.courier || 'N/A'}</td>
                            <td><span class="status-badge ${statusClass}">${s.status}</span></td>
                            <td>${s.current_location || 'N/A'}</td>
                            <td>${s.estimated_delivery ? new Date(s.estimated_delivery).toLocaleDateString() : 'N/A'}</td>
                        </tr>
                    `;
                    }).join('');
                    
                    submoduleContent = `
                        <p class="mb-6 text-gray-500">Track shipments and monitor real-time delivery status.</p>
                        <div class="kpi-card p-6">
                            <h3 class="text-xl font-semibold mb-4">Shipment Tracking (${shipmentsData.length} Shipments)</h3>
                            <div class="table-container" style="overflow-x: auto;">
                                <table class="data-table">
                                    <thead>
                                        <tr>
                                            <th>Tracking #</th>
                                            <th>Order #</th>
                                            <th>Customer</th>
                                            <th>Courier</th>
                                            <th>Status</th>
                                            <th>Current Location</th>
                                            <th>Est. Delivery</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        ${shipmentsData.length > 0 ? shipmentRows : `<tr><td colspan="7" class="text-center text-gray-500 py-4">No shipments found.</td></tr>`}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    `;
                    break;
            }

            content.innerHTML = `<h2 class="page-header">${moduleTitle}</h2>${submoduleContent}`;
            lucide.createIcons();
        }

        // 5. User & Role Management
        function renderUserModule(submodule) {
            setPageTitle('User & Role Management');
            const content = document.getElementById('content-container');
            let moduleTitle = 'User & Role Management';
            let submoduleContent = '';
            
            const currentUsername = adminDetails.username || "<?php echo $admin_username; ?>";
            const currentRole = adminDetails.role || "<?php echo $admin_role; ?>";
            const currentFullName = adminDetails.full_name || '';
            const currentEmail = adminDetails.email || '';
            const currentPhoneNumber = adminDetails.phone_number || '';

            switch (submodule) {
                case 'profile':
                    moduleTitle = 'Admin Profile (Functional Update)';
                    const accountCreatedAt = adminDetails.created_at ? new Date(adminDetails.created_at).toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' }) : 'N/A';
                    const lastUpdated = adminDetails.updated_at ? new Date(adminDetails.updated_at).toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' }) : 'N/A';
                    
                    submoduleContent = `
                        <div class="module-container" style="grid-template-columns: 1fr; gap: 1.5rem;">
                            <!-- Profile Header Card -->
                            <div class="kpi-card" style="background: linear-gradient(135deg, var(--color-primary-dark) 0%, var(--color-dark-grey) 100%); color: white; padding: 2.5rem;">
                                <div style="display: flex; gap: 2rem; align-items: flex-start; flex-wrap: wrap;">
                                    <div style="position: relative; flex-shrink: 0;">
                                        <img id="profile-avatar" 
                                            src="https://placehold.co/140x140/4bc5ec/FFFFFF?text=${currentUsername.charAt(0).toUpperCase() || 'A'}" 
                                            alt="Admin Avatar"
                                            style="width: 140px; height: 140px; border-radius: 50%; border: 4px solid rgba(255,255,255,0.3); object-fit: cover; box-shadow: 0 8px 16px rgba(0,0,0,0.2);">
                                        <button type="button" 
                                            onclick="showCustomActionModal('Picture Upload', 'Picture upload feature will be available soon.', 'OK')"
                                            style="position: absolute; bottom: 10px; right: 10px; background: var(--color-white); color: var(--color-primary-dark); border: none; border-radius: 50%; width: 36px; height: 36px; display: flex; align-items: center; justify-content: center; cursor: pointer; box-shadow: 0 4px 8px rgba(0,0,0,0.2); transition: transform 0.2s;"
                                            onmouseover="this.style.transform='scale(1.1)'"
                                            onmouseout="this.style.transform='scale(1)'">
                                            <i data-lucide="camera" style="width: 18px; height: 18px;"></i>
                                        </button>
                                    </div>
                                    <div style="flex: 1; min-width: 250px;">
                                        <div style="display: flex; align-items: center; gap: 1rem; margin-bottom: 0.75rem;">
                                            <h2 style="font-size: 2rem; font-weight: 800; margin: 0; color: white;">${currentFullName || currentUsername}</h2>
                                            <span style="background: rgba(255,255,255,0.2); padding: 0.25rem 0.75rem; border-radius: 9999px; font-size: 0.75rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em;">
                                                ${currentRole}
                                            </span>
                                        </div>
                                        <p style="font-size: 1.125rem; margin: 0 0 0.5rem 0; color: rgba(255,255,255,0.9); font-weight: 500;">@${currentUsername}</p>
                                        ${currentEmail ? `<p style="font-size: 0.9375rem; margin: 0.25rem 0; color: rgba(255,255,255,0.8); display: flex; align-items: center; gap: 0.5rem;">
                                            <i data-lucide="mail" style="width: 16px; height: 16px;"></i> ${currentEmail}
                                        </p>` : ''}
                                        ${currentPhoneNumber ? `<p style="font-size: 0.9375rem; margin: 0.25rem 0; color: rgba(255,255,255,0.8); display: flex; align-items: center; gap: 0.5rem;">
                                            <i data-lucide="phone" style="width: 16px; height: 16px;"></i> ${currentPhoneNumber}
                                        </p>` : ''}
                                    </div>
                                </div>
                                <div style="margin-top: 2rem; padding-top: 1.5rem; border-top: 1px solid rgba(255,255,255,0.2); display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 1.5rem;">
                                    <div>
                                        <p style="font-size: 0.75rem; color: rgba(255,255,255,0.7); margin: 0 0 0.25rem 0; text-transform: uppercase; letter-spacing: 0.05em;">Member Since</p>
                                        <p style="font-size: 0.9375rem; color: white; margin: 0; font-weight: 600;">${accountCreatedAt}</p>
                                    </div>
                                    <div>
                                        <p style="font-size: 0.75rem; color: rgba(255,255,255,0.7); margin: 0 0 0.25rem 0; text-transform: uppercase; letter-spacing: 0.05em;">Last Updated</p>
                                        <p style="font-size: 0.9375rem; color: white; margin: 0; font-weight: 600;">${lastUpdated}</p>
                                    </div>
                                    <div>
                                        <p style="font-size: 0.75rem; color: rgba(255,255,255,0.7); margin: 0 0 0.25rem 0; text-transform: uppercase; letter-spacing: 0.05em;">Status</p>
                                        <p style="font-size: 0.9375rem; color: #10b981; margin: 0; font-weight: 600; display: flex; align-items: center; gap: 0.5rem;">
                                            <i data-lucide="check-circle" style="width: 16px; height: 16px;"></i> Active
                                        </p>
                                    </div>
                                </div>
                            </div>

                            <!-- Profile Edit Form Card -->
                            <div class="kpi-card p-6">
                                <div style="display: flex; align-items: center; gap: 0.75rem; margin-bottom: 2rem; padding-bottom: 1rem; border-bottom: 2px solid var(--color-gray-100);">
                                    <div style="background: var(--color-indigo-600); padding: 0.75rem; border-radius: 0.5rem; display: flex; align-items: center; justify-content: center;">
                                        <i data-lucide="user-cog" style="width: 24px; height: 24px; color: white;"></i>
                                    </div>
                                    <div>
                                        <h3 style="font-size: 1.5rem; font-weight: 700; color: #1f2937; margin: 0;">Edit Profile Information</h3>
                                        <p style="font-size: 0.875rem; color: var(--color-gray-500); margin: 0.25rem 0 0 0;">Update your account details and preferences</p>
                                    </div>
                                </div>

                                <form id="profile-edit-form" method="POST" action="<?php echo basename(__FILE__); ?>" onsubmit="return validateProfileForm(event);">
                                    <input type="hidden" name="action" value="update_profile">
                                    <input type="hidden" name="module" value="user">
                                    <input type="hidden" name="submodule" value="profile">

                                    <!-- Personal Information Section -->
                                    <div style="margin-bottom: 2.5rem;">
                                        <h4 style="font-size: 1.125rem; font-weight: 600; color: #1f2937; margin-bottom: 1.5rem; display: flex; align-items: center; gap: 0.5rem;">
                                            <i data-lucide="user" style="width: 20px; height: 20px; color: var(--color-indigo-600);"></i>
                                            Personal Information
                                        </h4>
                                        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 1.5rem;">
                                            <div class="form-group">
                                                <label for="full_name" style="display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.5rem;">
                                                    <i data-lucide="user-circle" style="width: 16px; height: 16px; color: var(--color-gray-500);"></i>
                                                    Full Name
                                                </label>
                                                <input type="text" id="full_name" name="full_name" value="${currentFullName}" placeholder="Enter your full name" style="padding: 0.875rem 1rem; border: 1px solid var(--color-gray-300); border-radius: 0.5rem; font-size: 0.9375rem; transition: all 0.2s; width: 100%;">
                                            </div>
                                            
                                            <div class="form-group">
                                                <label for="new_username" style="display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.5rem;">
                                                    <i data-lucide="at-sign" style="width: 16px; height: 16px; color: var(--color-gray-500);"></i>
                                                    Username
                                                </label>
                                                <input type="text" id="new_username" name="new_username" value="${currentUsername}" required 
                                                    style="padding: 0.875rem 1rem; border: 1px solid var(--color-gray-300); border-radius: 0.5rem; font-size: 0.9375rem; transition: all 0.2s; width: 100%;">
                                            </div>
                                        </div>
                                    </div>

                                    <!-- Contact Information Section -->
                                    <div style="margin-bottom: 2.5rem;">
                                        <h4 style="font-size: 1.125rem; font-weight: 600; color: #1f2937; margin-bottom: 1.5rem; display: flex; align-items: center; gap: 0.5rem;">
                                            <i data-lucide="phone" style="width: 20px; height: 20px; color: var(--color-indigo-600);"></i>
                                            Contact Information
                                        </h4>
                                        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 1.5rem;">
                                            <div class="form-group">
                                                <label for="email" style="display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.5rem;">
                                                    <i data-lucide="mail" style="width: 16px; height: 16px; color: var(--color-gray-500);"></i>
                                                    Email Address <span style="color: var(--color-red-600);">*</span>
                                                </label>
                                                <input type="email" id="email" name="email" value="${currentEmail}" placeholder="Enter your email address" required 
                                                    style="padding: 0.875rem 1rem; border: 1px solid var(--color-gray-300); border-radius: 0.5rem; font-size: 0.9375rem; transition: all 0.2s; width: 100%;">
                                            </div>

                                            <div class="form-group">
                                                <label for="phone_number" style="display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.5rem;">
                                                    <i data-lucide="phone-call" style="width: 16px; height: 16px; color: var(--color-gray-500);"></i>
                                                    Mobile Number <span style="color: var(--color-gray-500); font-size: 0.75rem;">(Optional)</span>
                                                </label>
                                                <input type="tel" id="phone_number" name="phone_number" value="${currentPhoneNumber}" placeholder="Enter your mobile number" pattern="[0-9]*"
                                                    style="padding: 0.875rem 1rem; border: 1px solid var(--color-gray-300); border-radius: 0.5rem; font-size: 0.9375rem; transition: all 0.2s; width: 100%;">
                                            </div>
                                        </div>
                                    </div>

                                    <!-- Security Section -->
                                    <div style="margin-bottom: 2.5rem;">
                                        <div style="display: flex; align-items: center; gap: 0.75rem; margin-bottom: 1.5rem; padding-bottom: 1rem; border-bottom: 2px solid var(--color-gray-100);">
                                            <div style="background: #fee2e2; padding: 0.75rem; border-radius: 0.5rem; display: flex; align-items: center; justify-content: center;">
                                                <i data-lucide="shield" style="width: 20px; height: 20px; color: var(--color-red-600);"></i>
                                            </div>
                                            <div>
                                                <h4 style="font-size: 1.125rem; font-weight: 600; color: #1f2937; margin: 0;">Password & Security</h4>
                                                <p style="font-size: 0.875rem; color: var(--color-gray-500); margin: 0.25rem 0 0 0;">Change your password to keep your account secure</p>
                                            </div>
                                        </div>
                                        
                                        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 1.5rem;">
                                            <div class="form-group">
                                                <label for="current_password" style="display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.5rem;">
                                                    <i data-lucide="lock" style="width: 16px; height: 16px; color: var(--color-gray-500);"></i>
                                                    Current Password <span style="color: var(--color-red-600);">*</span>
                                                </label>
                                                <input type="password" id="current_password" name="current_password" placeholder="Enter current password" autocomplete="off" required 
                                                    style="padding: 0.875rem 1rem; border: 1px solid var(--color-gray-300); border-radius: 0.5rem; font-size: 0.9375rem; transition: all 0.2s; width: 100%;">
                                                <p style="font-size: 0.75rem; color: var(--color-gray-500); margin: 0.5rem 0 0 0;">Required to save any changes</p>
                                            </div>
                                        </div>

                                        <div style="margin-top: 1.5rem; padding: 1.5rem; background: var(--color-gray-100); border-radius: 0.5rem; border-left: 4px solid var(--color-indigo-600);">
                                            <p style="font-size: 0.875rem; font-weight: 600; color: #1f2937; margin: 0 0 0.75rem 0;">Change Password (Optional)</p>
                                            <p style="font-size: 0.8125rem; color: var(--color-gray-500); margin: 0 0 1rem 0;">Leave blank if you don't want to change your password</p>
                                            
                                            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 1.5rem;">
                                                <div class="form-group" style="margin-bottom: 0;">
                                                    <label for="new_password" style="display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.5rem;">
                                                        <i data-lucide="key" style="width: 16px; height: 16px; color: var(--color-gray-500);"></i>
                                                        New Password
                                                    </label>
                                                    <input type="password" id="new_password" name="new_password" placeholder="Enter new password (min 6 characters)" autocomplete="new-password"
                                                        style="padding: 0.875rem 1rem; border: 1px solid var(--color-gray-300); border-radius: 0.5rem; font-size: 0.9375rem; transition: all 0.2s; width: 100%;">
                                                </div>
                                                
                                                <div class="form-group" style="margin-bottom: 0;">
                                                    <label for="confirm_password" style="display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.5rem;">
                                                        <i data-lucide="key-round" style="width: 16px; height: 16px; color: var(--color-gray-500);"></i>
                                                        Confirm New Password
                                                    </label>
                                                    <input type="password" id="confirm_password" name="confirm_password" placeholder="Confirm new password" autocomplete="new-password"
                                                        style="padding: 0.875rem 1rem; border: 1px solid var(--color-gray-300); border-radius: 0.5rem; font-size: 0.9375rem; transition: all 0.2s; width: 100%;">
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                    
                                    <!-- Action Buttons -->
                                    <div style="display: flex; gap: 1rem; padding-top: 2rem; border-top: 2px solid var(--color-gray-100); margin-top: 1rem;">
                                        <button type="submit" class="btn-base btn-primary" style="padding: 0.875rem 2rem; font-size: 1rem; font-weight: 600; display: flex; align-items: center; gap: 0.5rem;">
                                            <i data-lucide="save" style="width: 20px; height: 20px;"></i>
                                            Save Changes
                                        </button>
                                        <button type="button" class="btn-base btn-secondary" onclick="window.location.reload()" style="padding: 0.875rem 2rem; font-size: 1rem; font-weight: 600; display: flex; align-items: center; gap: 0.5rem;">
                                            <i data-lucide="x" style="width: 20px; height: 20px;"></i>
                                            Cancel
                                        </button>
                                    </div>
                                </form>
                            </div>
                        </div>
                    `;
                    break;
                case 'admins':
                    moduleTitle = 'Admin Accounts & Role-Based Access Control (RBAC)';
                    const adminRows = adminUsersData.map(a => `
                        <tr>
                            <td>${a.username}</td>
                            <td>${a.full_name || 'N/A'}</td>
                            <td>${a.email || 'N/A'}</td>
                            <td>${a.role}</td>
                            <td>${new Date(a.created_at).toLocaleDateString()}</td>
                            <td style="width: 100px;">
                                ${a.id != <?php echo $_SESSION['admin_id'] ?? 0; ?> ? `
                                <button class="btn-base" style="padding: 0.25rem 0.5rem; background-color: var(--color-red-600); color: white;"
                                    onclick="deleteAdmin(${a.id}, '${a.username.replace(/'/g, "\\'")}')">
                                    <i data-lucide="trash-2" style="width: 1rem; height: 1rem;"></i>
                                </button>
                                ` : '<span class="text-gray-400 text-sm">Current User</span>'}
                            </td>
                        </tr>
                    `).join('');
                    
                    submoduleContent = `
                        <p class="mb-6 text-gray-500">Manage admin accounts and role-based access control.</p>
                        <div class="kpi-card p-6">
                            <h3 class="text-xl font-semibold mb-4">Admin/Staff List (${adminUsersData.length} Admins)</h3>
                            <div class="table-container" style="overflow-x: auto;">
                                <table class="data-table">
                                    <thead>
                                        <tr>
                                            <th>Username</th>
                                            <th>Full Name</th>
                                            <th>Email</th>
                                            <th>Role</th>
                                            <th>Created</th>
                                            <th>Actions</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        ${adminUsersData.length > 0 ? adminRows : `<tr><td colspan="6" class="text-center text-gray-500 py-4">No admin users found.</td></tr>`}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    `;
                    break;
                case 'customers':
                    moduleTitle = 'Customer List';
                    const customerRows = customersData.map(c => {
                        const statusClass = c.status === 'Active' ? 'active' : (c.status === 'Banned' ? 'cancelled' : 'inactive');
                        return `
                        <tr>
                            <td>${c.full_name}</td>
                            <td>${c.email}</td>
                            <td>${c.phone_number || 'N/A'}</td>
                            <td>${c.total_orders || 0}</td>
                            <td>${c.total_spent ? formatCurrency(parseFloat(c.total_spent)) : '$0.00'}</td>
                            <td><span class="status-badge ${statusClass}">${c.status}</span></td>
                            <td>${new Date(c.created_at).toLocaleDateString()}</td>
                        </tr>
                    `;
                    }).join('');
                    
                    submoduleContent = `
                        <p class="mb-6 text-gray-500">View all customers, their order history, and account status.</p>
                        <div class="kpi-card p-6">
                            <h3 class="text-xl font-semibold mb-4">Customer Directory (${customersData.length} Customers)</h3>
                            <div class="table-container" style="overflow-x: auto;">
                                <table class="data-table">
                                    <thead>
                                        <tr>
                                            <th>Name</th>
                                            <th>Email</th>
                                            <th>Phone</th>
                                            <th>Total Orders</th>
                                            <th>Total Spent</th>
                                            <th>Status</th>
                                            <th>Joined</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        ${customersData.length > 0 ? customerRows : `<tr><td colspan="7" class="text-center text-gray-500 py-4">No customers found.</td></tr>`}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    `;
                    break;
            }

            content.innerHTML = `<h2 class="page-header">${moduleTitle}</h2>${submoduleContent}`;
            lucide.createIcons();
        }
        
        // Form Validation for Profile Update
        function validateProfileForm(event) {
            const newPass = document.getElementById('new_password').value;
            const confirmPass = document.getElementById('confirm_password').value;
            
            if (newPass && newPass.length < 6) {
                showCustomActionModal('Error', 'New password must be at least 6 characters long.', 'OK');
                return false;
            }

            if (newPass && newPass !== confirmPass) {
                showCustomActionModal('Error', 'New password and confirmation password do not match.', 'OK');
                return false;
            }
            
            // If valid, submit the form via the custom modal to handle the POST logic
            showCustomActionModal('Confirm Update', 'Are you sure you want to save these profile changes?', 'Confirm Save', () => event.target.submit());

            // Prevent default submission here as we use the callback in the modal
            return false;
        }

        // 6. Customer Support Center
        function renderSupportModule() {
            setPageTitle('Customer Support Center');
            const content = document.getElementById('content-container');
            
            const ticketRows = supportTicketsData.map(t => {
                const statusClass = t.status === 'Resolved' ? 'active' : (t.status === 'In Progress' ? 'processing' : (t.status === 'Closed' ? 'inactive' : 'pending'));
                const priorityClass = t.priority === 'Urgent' ? 'critical-stock' : (t.priority === 'High' ? 'low-stock' : 'active');
                return `
                <tr>
                    <td>${t.ticket_number}</td>
                    <td>${t.customer_name || 'N/A'}</td>
                    <td>${t.subject}</td>
                    <td><span class="status-badge ${statusClass}">${t.status}</span></td>
                    <td><span class="status-badge ${priorityClass}">${t.priority}</span></td>
                    <td>${t.assigned_admin || 'Unassigned'}</td>
                    <td>${new Date(t.created_at).toLocaleDateString()}</td>
                    <td style="width: 100px;">
                        <button class="btn-base" style="padding: 0.25rem 0.5rem; background-color: var(--color-light-grey);" 
                            onclick="showTicketDetails(${t.id})">
                            <i data-lucide="eye" style="width: 1rem; height: 1rem;"></i>
                        </button>
                    </td>
                </tr>
            `;
            }).join('');
            
            const openTickets = supportTicketsData.filter(t => t.status === 'Open' || t.status === 'In Progress').length;
            const resolvedTickets = supportTicketsData.filter(t => t.status === 'Resolved' || t.status === 'Closed').length;
            
            content.innerHTML = `
                <h2 class="page-header">Customer Support Center</h2>
                <p class="mb-6 text-gray-500">Manage support tickets and customer communications.</p>
                
                <div class="kpi-card-grid" style="margin-bottom: 2rem;">
                    ${createKPICard('Open Tickets', openTickets, 'message-square', 'kpi-yellow')}
                    ${createKPICard('Resolved', resolvedTickets, 'check-circle', 'kpi-green')}
                    ${createKPICard('Total Tickets', supportTicketsData.length, 'ticket', 'kpi-indigo')}
                    ${createKPICard('High Priority', supportTicketsData.filter(t => t.priority === 'High' || t.priority === 'Urgent').length, 'alert-triangle', 'kpi-red')}
                </div>
                
                <div class="kpi-card p-6">
                    <h3 class="text-xl font-semibold mb-4">Support Tickets (${supportTicketsData.length} Total)</h3>
                    <div class="table-container" style="overflow-x: auto;">
                        <table class="data-table">
                            <thead>
                                <tr>
                                    <th>Ticket #</th>
                                    <th>Customer</th>
                                    <th>Subject</th>
                                    <th>Status</th>
                                    <th>Priority</th>
                                    <th>Assigned To</th>
                                    <th>Created</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${supportTicketsData.length > 0 ? ticketRows : `<tr><td colspan="8" class="text-center text-gray-500 py-4">No support tickets found.</td></tr>`}
                            </tbody>
                        </table>
                    </div>
                </div>
            `;
            lucide.createIcons();
        }
        
        function showTicketDetails(ticketId) {
            const ticket = supportTicketsData.find(t => t.id == ticketId);
            if (!ticket) return;
            
            const formHTML = `
                <form id="ticket-form" method="POST" action="<?php echo basename(__FILE__); ?>">
                    <input type="hidden" name="action" value="update_ticket">
                    <input type="hidden" name="id" value="${ticket.id}">
                    <input type="hidden" name="module" value="support">
                    
                    <div style="margin-bottom: 1.5rem;">
                        <p><strong>Ticket:</strong> ${ticket.ticket_number}</p>
                        <p><strong>Customer:</strong> ${ticket.customer_name || 'N/A'}</p>
                        <p><strong>Subject:</strong> ${ticket.subject}</p>
                        <p><strong>Message:</strong></p>
                        <div style="padding: 1rem; background: #f3f4f6; border-radius: 0.5rem; margin-top: 0.5rem;">${ticket.message}</div>
                    </div>
                    
                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-bottom: 1.5rem;">
                        <div class="form-group">
                            <label>Status</label>
                            <select name="status" 
                                style="width: 100%; padding: 0.75rem; border: 1px solid var(--color-gray-300); border-radius: 0.5rem;">
                                <option value="Open" ${ticket.status === 'Open' ? 'selected' : ''}>Open</option>
                                <option value="In Progress" ${ticket.status === 'In Progress' ? 'selected' : ''}>In Progress</option>
                                <option value="Resolved" ${ticket.status === 'Resolved' ? 'selected' : ''}>Resolved</option>
                                <option value="Closed" ${ticket.status === 'Closed' ? 'selected' : ''}>Closed</option>
                            </select>
                        </div>
                        
                        <div class="form-group">
                            <label>Priority</label>
                            <select name="priority" 
                                style="width: 100%; padding: 0.75rem; border: 1px solid var(--color-gray-300); border-radius: 0.5rem;">
                                <option value="Low" ${ticket.priority === 'Low' ? 'selected' : ''}>Low</option>
                                <option value="Medium" ${ticket.priority === 'Medium' ? 'selected' : ''}>Medium</option>
                                <option value="High" ${ticket.priority === 'High' ? 'selected' : ''}>High</option>
                                <option value="Urgent" ${ticket.priority === 'Urgent' ? 'selected' : ''}>Urgent</option>
                            </select>
                        </div>
                    </div>
                    
                    <div style="display: flex; gap: 1rem; margin-top: 2rem;">
                        <button type="submit" class="btn-base btn-primary" style="flex: 1;">Update Ticket</button>
                        <button type="button" class="btn-base btn-secondary" onclick="document.getElementById('custom-modal-backdrop').classList.add('hidden')" style="flex: 1;">Close</button>
                    </div>
                </form>
            `;
            
            const modalContainer = document.getElementById('modal-container');
            modalContainer.innerHTML = `
                <h3 style="font-size: 1.25rem; font-weight: 700; color: #1f2937; margin-bottom: 1.5rem;">Ticket Details</h3>
                <div id="modal-form-content">${formHTML}</div>
            `;
            document.getElementById('custom-modal-backdrop').classList.remove('hidden');
        }
        
        function deleteAdmin(id, username) {
            showCustomActionModal(
                'Delete Admin User',
                `Are you sure you want to delete admin user <strong>${username}</strong>? This action cannot be undone.`,
                'Delete',
                () => {
                    const form = document.createElement('form');
                    form.method = 'POST';
                    form.action = '<?php echo basename(__FILE__); ?>';
                    form.innerHTML = `
                        <input type="hidden" name="action" value="delete_admin">
                        <input type="hidden" name="id" value="${id}">
                        <input type="hidden" name="module" value="user">
                        <input type="hidden" name="submodule" value="admins">
                    `;
                    document.body.appendChild(form);
                    form.submit();
                }
            );
        }

        // 7. Notification & Alert System
        function renderAlertsModule() {
            setPageTitle('Notification & Alert System');
            const content = document.getElementById('content-container');
            
            // Generate real alerts based on data
            const lowStockProducts = productsData.filter(p => parseInt(p.stock) < 10 && p.status !== 'Inactive');
            const pendingOrders = ordersData.filter(o => o.status === 'Pending');
            const openTickets = supportTicketsData.filter(t => t.status === 'Open' || t.status === 'In Progress');
            const pendingTransactions = transactionsData.filter(t => t.status === 'Pending');
            
            const alertsList = [];
            
            if (lowStockProducts.length > 0) {
                alertsList.push({
                    type: 'warning',
                    icon: 'alert-triangle',
                    title: 'Low Stock Alert',
                    message: `${lowStockProducts.length} product(s) are running low on stock (less than 10 units)`,
                    count: lowStockProducts.length
                });
            }
            
            if (pendingOrders.length > 0) {
                alertsList.push({
                    type: 'info',
                    icon: 'shopping-cart',
                    title: 'Pending Orders',
                    message: `${pendingOrders.length} order(s) are pending approval`,
                    count: pendingOrders.length
                });
            }
            
            if (openTickets.length > 0) {
                alertsList.push({
                    type: 'warning',
                    icon: 'message-square',
                    title: 'Open Support Tickets',
                    message: `${openTickets.length} support ticket(s) require attention`,
                    count: openTickets.length
                });
            }
            
            if (pendingTransactions.length > 0) {
                alertsList.push({
                    type: 'info',
                    icon: 'dollar-sign',
                    title: 'Pending Payments',
                    message: `${pendingTransactions.length} transaction(s) are pending`,
                    count: pendingTransactions.length
                });
            }
            
            const alertsHTML = alertsList.map(alert => `
                <div class="p-4 rounded-lg mb-3" style="background-color: ${alert.type === 'warning' ? '#fffbe6' : '#e0e7ff'}; border: 1px solid ${alert.type === 'warning' ? '#f59e0b' : '#4f46e5'};">
                    <div style="display: flex; align-items: center; gap: 1rem;">
                        <div style="padding: 0.5rem; background: ${alert.type === 'warning' ? '#f59e0b' : '#4f46e5'}; border-radius: 0.5rem; color: white;">
                            <i data-lucide="${alert.icon}" style="width: 1.5rem; height: 1.5rem;"></i>
                        </div>
                        <div style="flex: 1;">
                            <h4 style="font-weight: 600; color: #1f2937; margin-bottom: 0.25rem;">${alert.title}</h4>
                            <p style="font-size: 0.875rem; color: #6b7280; margin: 0;">${alert.message}</p>
                        </div>
                        <span style="background: ${alert.type === 'warning' ? '#f59e0b' : '#4f46e5'}; color: white; padding: 0.25rem 0.75rem; border-radius: 9999px; font-size: 0.75rem; font-weight: 600;">${alert.count}</span>
                    </div>
                </div>
            `).join('');
            
            content.innerHTML = `
                <h2 class="page-header">Notification & Alert System</h2>
                <p class="mb-6 text-gray-500">Manage system alerts and send broadcast messages to customers.</p>
                
                <div class="module-container" style="display: grid; grid-template-columns: repeat(auto-fit, minmax(400px, 1fr)); gap: 1.5rem;">
                    <div class="kpi-card p-6">
                        <h3 class="text-xl font-semibold mb-4">System Alerts (${alertsList.length} Active)</h3>
                        ${alertsList.length > 0 ? alertsHTML : '<div class="p-3 text-sm text-center text-gray-500 rounded-lg" style="border: 1px solid #e5e7eb;">No active system alerts. All systems operational.</div>'}
                    </div>

                    <div class="kpi-card p-6">
                        <h3 class="text-xl font-semibold mb-4">Broadcast Message</h3>
                        <textarea id="broadcast-message" style="width: 100%; padding: 0.75rem; border: 1px solid #d1d5db; border-radius: 0.5rem; outline: none;" rows="4" placeholder="Enter message for Email/SMS Broadcast..."></textarea>
                        <select id="broadcast-audience" style="margin-top: 0.75rem; width: 100%; padding: 0.75rem; border: 1px solid #d1d5db; border-radius: 0.5rem; outline: none;">
                            <option>Send to All Customers</option>
                            <option>Send to Active Customers Only</option>
                        </select>
                        <button class="btn-base btn-primary w-full" style="margin-top: 1rem; padding: 0.75rem 1.25rem;" 
                            onclick="showCustomActionModal('Send Broadcast', 'Are you sure you want to send this broadcast message?', 'Send', () => console.log('Broadcast message sent'))">
                            <i data-lucide="send" style="width: 1rem; height: 1rem; margin-right: 0.5rem;"></i>
                            Send Broadcast
                        </button>
                    </div>
                </div>
            `;
            lucide.createIcons();
        }

        // 8. System Settings & Security
        function renderSettingsModule() {
            setPageTitle('System Settings & Security');
            const content = document.getElementById('content-container');
            content.innerHTML = `
                <h2 class="page-header">System Settings & Security</h2>
                <p class="mb-6 text-gray-500">Protect system integrity and ensure compliance.</p>
                
                <div class="module-container" style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 1.5rem;">
                    <div class="kpi-card p-6 space-y-4">
                        <h3 class="text-xl font-semibold pb-2" style="border-bottom: 1px solid #e5e7eb;">Database and Audit</h3>
                        <div class="flex justify-between items-center">
                            <span>Backup and Restore Database</span>
                            <button class="btn-base btn-secondary" style="padding: 0.5rem 1rem;" 
                                onclick="showCustomActionModal('Database Backup', 'Are you sure you want to initiate a full database backup now?', 'Backup', () => console.log('Backup initiated'))">Execute Backup</button>
                        </div>
                        <div style="border-bottom: 1px solid #e5e7eb; padding-bottom: 1rem;">
                            <div class="flex justify-between items-center mb-3">
                                <span>View Audit Logs</span>
                                <button class="btn-base btn-secondary" style="padding: 0.5rem 1rem;" 
                                    onclick="showCustomActionModal('System Audit', 'The complete audit log history would load in a new window/tab.', 'View')">View Logs</button>
                            </div>
                            <p class="text-sm text-gray-500">*(Record who changed what)*</p>
                        </div>
                        
                    </div>

                    <div class="kpi-card p-6 space-y-4">
                        <h3 class="text-xl font-semibold pb-2" style="border-bottom: 1px solid #e5e7eb;">Security & API</h3>
                        <div class="flex justify-between items-center">
                            <span>API Key Management</span>
                            <button class="btn-base btn-secondary" style="padding: 0.5rem 1rem;" 
                                onclick="showCustomActionModal('API Key Management', 'The interface to manage, generate, and revoke API keys would open here.', 'OK')">Manage Keys</button>
                        </div>
                        <div class="flex justify-between items-center">
                            <span>SSL / Firewall Monitoring</span>
                            <span class="text-green-600 font-bold" style="color: var(--color-green-600);">Status: Secure</span>
                        </div>
                    </div>
                </div>
            `;
            lucide.createIcons();
        }

        // --- MAIN ROUTER ---
        function showModule(moduleName, element = null) {
            
            // Close all submenus when switching main modules
            document.querySelectorAll('.submenu').forEach(sub => sub.classList.add('hidden'));
            document.querySelectorAll('.nav-item .chevron-icon').forEach(icon => {
                icon.classList.remove('rotate-90');
            });
            
            // Set the clicked main module or default module to active
            let navElement = element;
            if (!navElement) {
                navElement = document.querySelector(`.nav-menu a[onclick*="'${moduleName}'"]`);
            }
            if (navElement) {
                setActiveNav(navElement);
            }
            
            // Render the content based on the module
            switch (moduleName) {
                case 'dashboard':
                    renderDashboard();
                    break;
                case 'product':
                    // Default to product list
                    showSubModule('product', 'products');
                    break;
                case 'order':
                    // Default to view all orders
                    showSubModule('order', 'orders');
                    break;
                case 'shipping':
                    // Default to addresses
                    showSubModule('shipping', 'addresses');
                    break;
                case 'support':
                    renderSupportModule();
                    break;
                case 'alerts':
                    renderAlertsModule();
                    break;
                case 'settings':
                    renderSettingsModule();
                    break;
                default:
                    renderDashboard();
                    break;
            }
            window.scrollTo(0, 0);
        }

        function showSubModule(modulePrefix, submodule) {
            const moduleMap = {
                'product': renderProductModule,
                'order': renderOrderModule,
                'shipping': renderShippingModule,
                'user': renderUserModule,
            };

            if (moduleMap[modulePrefix]) {
                moduleMap[modulePrefix](submodule);
                
                // --- Navigation Fix for Submodules ---
                // 1. Find the specific submenu link
                const submenuLink = document.querySelector(`.submenu a[onclick*="'${submodule}'"]`);
                
                // 2. Clear all active states
                document.querySelectorAll('.nav-menu a').forEach(item => item.classList.remove('active-nav'));
                
                if (submenuLink) {
                    // 3. Set submenu link to active
                    submenuLink.classList.add('active-nav'); 
                    
                    // 4. Set parent navigation item to active AND ensure its submenu is open
                    const parentGroup = submenuLink.closest('.group');
                    const parentNav = parentGroup.querySelector('.nav-item');
                    if (parentNav) {
                        parentNav.classList.add('active-nav');
                        const submenu = parentGroup.querySelector('.submenu');
                        const icon = parentNav.querySelector('.chevron-icon');
                         if (submenu && submenu.classList.contains('hidden')) {
                            submenu.classList.remove('hidden');
                            icon.classList.add('rotate-90');
                        }
                    }
                }
            }
            window.scrollTo(0, 0);
        }

        // --- PRODUCT FORM FUNCTIONS ---
        function showProductForm(productId = null) {
            const product = productId ? productsData.find(p => p.id == productId) : null;
            const isEdit = !!product;
            const categoryOptions = categoriesData.map(cat => 
                `<option value="${cat.id}" ${product && product.category_id == cat.id ? 'selected' : ''}>${cat.name}</option>`
            ).join('');
            
            const formHTML = `
                <form id="product-form" method="POST" action="<?php echo basename(__FILE__); ?>">
                    <input type="hidden" name="action" value="${isEdit ? 'edit_product' : 'add_product'}">
                    <input type="hidden" name="module" value="product">
                    <input type="hidden" name="submodule" value="products">
                    ${isEdit ? `<input type="hidden" name="id" value="${product.id}">` : ''}
                    
                    <div class="form-group" style="margin-bottom: 1.5rem;">
                        <label>Product Name *</label>
                        <input type="text" name="name" value="${product ? product.name.replace(/"/g, '&quot;') : ''}" required 
                            style="width: 100%; padding: 0.75rem; border: 1px solid var(--color-gray-300); border-radius: 0.5rem;">
                    </div>
                    
                    <div class="form-group" style="margin-bottom: 1.5rem;">
                        <label>Description</label>
                        <textarea name="description" rows="3" 
                            style="width: 100%; padding: 0.75rem; border: 1px solid var(--color-gray-300); border-radius: 0.5rem;">${product ? (product.description || '').replace(/"/g, '&quot;') : ''}</textarea>
                    </div>
                    
                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-bottom: 1.5rem;">
                        <div class="form-group">
                            <label>Price *</label>
                            <input type="number" name="price" step="0.01" value="${product ? product.price : ''}" required 
                                style="width: 100%; padding: 0.75rem; border: 1px solid var(--color-gray-300); border-radius: 0.5rem;">
                        </div>
                        
                        <div class="form-group">
                            <label>Stock Quantity *</label>
                            <input type="number" name="stock" value="${product ? product.stock : ''}" required 
                                style="width: 100%; padding: 0.75rem; border: 1px solid var(--color-gray-300); border-radius: 0.5rem;">
                        </div>
                    </div>
                    
                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-bottom: 1.5rem;">
                        <div class="form-group">
                            <label>Category *</label>
                            <select name="category_id" required 
                                style="width: 100%; padding: 0.75rem; border: 1px solid var(--color-gray-300); border-radius: 0.5rem;">
                                <option value="">Select Category</option>
                                ${categoryOptions}
                            </select>
                        </div>
                        
                        <div class="form-group">
                            <label>Status</label>
                            <select name="status" 
                                style="width: 100%; padding: 0.75rem; border: 1px solid var(--color-gray-300); border-radius: 0.5rem;">
                                <option value="Active" ${product && product.status === 'Active' ? 'selected' : ''}>Active</option>
                                <option value="Inactive" ${product && product.status === 'Inactive' ? 'selected' : ''}>Inactive</option>
                                <option value="Low Stock" ${product && product.status === 'Low Stock' ? 'selected' : ''}>Low Stock</option>
                                <option value="Critical Stock" ${product && product.status === 'Critical Stock' ? 'selected' : ''}>Critical Stock</option>
                            </select>
                        </div>
                    </div>
                    
                    <div class="form-group" style="margin-bottom: 1.5rem;">
                        <label>Image URL (Optional)</label>
                        <input type="url" name="image_url" value="${product ? (product.image_url || '') : ''}" 
                            placeholder="https://example.com/image.jpg"
                            style="width: 100%; padding: 0.75rem; border: 1px solid var(--color-gray-300); border-radius: 0.5rem;">
                        <small style="color: #6b7280; font-size: 0.75rem; margin-top: 0.25rem; display: block;">Enter a URL to an image for this product</small>
                    </div>
                    
                    <div style="display: flex; gap: 1rem; margin-top: 2rem;">
                        <button type="submit" class="btn-base btn-primary" style="flex: 1; padding: 0.75rem; font-weight: 600;">
                            <i data-lucide="${isEdit ? 'save' : 'plus'}" style="width: 1rem; height: 1rem; margin-right: 0.5rem;"></i>
                            ${isEdit ? 'Update Product' : 'Add Product'}
                        </button>
                        <button type="button" class="btn-base btn-secondary" onclick="document.getElementById('custom-modal-backdrop').classList.add('hidden')" style="flex: 1; padding: 0.75rem;">
                            Cancel
                        </button>
                    </div>
                </form>
            `;
            
            const modalContainer = document.getElementById('modal-container');
            modalContainer.innerHTML = `
                <h3 style="font-size: 1.25rem; font-weight: 700; color: #1f2937; margin-bottom: 1.5rem;">${isEdit ? 'Edit Product' : 'Add New Product'}</h3>
                <div id="modal-form-content">${formHTML}</div>
            `;
            document.getElementById('custom-modal-backdrop').classList.remove('hidden');
        }
        
        function deleteProduct(id, name) {
            showCustomActionModal(
                'Delete Product',
                `Are you sure you want to delete <strong>${name}</strong>? This action cannot be undone.`,
                'Delete',
                () => {
                    const form = document.createElement('form');
                    form.method = 'POST';
                    form.action = '<?php echo basename(__FILE__); ?>';
                    form.innerHTML = `
                        <input type="hidden" name="action" value="delete_product">
                        <input type="hidden" name="id" value="${id}">
                        <input type="hidden" name="module" value="product">
                        <input type="hidden" name="submodule" value="products">
                    `;
                    document.body.appendChild(form);
                    form.submit();
                }
            );
        }
        
        function clearAllProducts() {
            const productCount = productsData.length;
            showCustomActionModal(
                'Clear All Products',
                `Are you sure you want to delete <strong>ALL ${productCount} product(s)</strong> from the database?<br><br><strong style="color: #ef4444;">This action cannot be undone!</strong><br>All sample products will be permanently removed.`,
                'Delete All',
                () => {
                    const form = document.createElement('form');
                    form.method = 'POST';
                    form.action = '<?php echo basename(__FILE__); ?>';
                    form.innerHTML = `
                        <input type="hidden" name="action" value="clear_all_products">
                        <input type="hidden" name="module" value="product">
                        <input type="hidden" name="submodule" value="products">
                    `;
                    document.body.appendChild(form);
                    form.submit();
                }
            );
        }
        
        // --- CATEGORY FORM FUNCTIONS ---
        function showCategoryForm(categoryId = null) {
            const category = categoryId ? categoriesData.find(c => c.id == categoryId) : null;
            const isEdit = !!category;
            
            const formHTML = `
                <form id="category-form" method="POST" action="<?php echo basename(__FILE__); ?>">
                    <input type="hidden" name="action" value="${isEdit ? 'edit_category' : 'add_category'}">
                    <input type="hidden" name="module" value="product">
                    <input type="hidden" name="submodule" value="categories">
                    ${isEdit ? `<input type="hidden" name="id" value="${category.id}">` : ''}
                    
                    <div class="form-group" style="margin-bottom: 1.5rem;">
                        <label>Category Name *</label>
                        <input type="text" name="name" value="${category ? category.name.replace(/"/g, '&quot;') : ''}" required 
                            style="width: 100%; padding: 0.75rem; border: 1px solid var(--color-gray-300); border-radius: 0.5rem;">
                    </div>
                    
                    <div class="form-group" style="margin-bottom: 1.5rem;">
                        <label>Description</label>
                        <textarea name="description" rows="3" 
                            style="width: 100%; padding: 0.75rem; border: 1px solid var(--color-gray-300); border-radius: 0.5rem;">${category ? (category.description || '').replace(/"/g, '&quot;') : ''}</textarea>
                    </div>
                    
                    <div class="form-group" style="margin-bottom: 1.5rem;">
                        <label>Status</label>
                        <select name="status" 
                            style="width: 100%; padding: 0.75rem; border: 1px solid var(--color-gray-300); border-radius: 0.5rem;">
                            <option value="Active" ${category && category.status === 'Active' ? 'selected' : ''}>Active</option>
                            <option value="Inactive" ${category && category.status === 'Inactive' ? 'selected' : ''}>Inactive</option>
                        </select>
                    </div>
                    
                    <div style="display: flex; gap: 1rem; margin-top: 2rem;">
                        <button type="submit" class="btn-base btn-primary" style="flex: 1;">
                            ${isEdit ? 'Update Category' : 'Add Category'}
                        </button>
                        <button type="button" class="btn-base btn-secondary" onclick="document.getElementById('custom-modal-backdrop').classList.add('hidden')" style="flex: 1;">
                            Cancel
                        </button>
                    </div>
                </form>
            `;
            
            const modalContainer = document.getElementById('modal-container');
            modalContainer.innerHTML = `
                <h3 style="font-size: 1.25rem; font-weight: 700; color: #1f2937; margin-bottom: 1.5rem;">${isEdit ? 'Edit Category' : 'Add New Category'}</h3>
                <div id="modal-form-content">${formHTML}</div>
            `;
            document.getElementById('custom-modal-backdrop').classList.remove('hidden');
        }
        
        function deleteCategory(id, name) {
            showCustomActionModal(
                'Delete Category',
                `Are you sure you want to delete category <strong>${name}</strong>? This action cannot be undone.`,
                'Delete',
                () => {
                    const form = document.createElement('form');
                    form.method = 'POST';
                    form.action = '<?php echo basename(__FILE__); ?>';
                    form.innerHTML = `
                        <input type="hidden" name="action" value="delete_category">
                        <input type="hidden" name="id" value="${id}">
                        <input type="hidden" name="module" value="product">
                        <input type="hidden" name="submodule" value="categories">
                    `;
                    document.body.appendChild(form);
                    form.submit();
                }
            );
        }

        // Initial load
        document.addEventListener('DOMContentLoaded', () => {
            if (document.querySelector('.sidebar')) {
                const urlParams = new URLSearchParams(window.location.search);
                const initialModule = urlParams.get('module') || 'dashboard';
                const initialSubmodule = urlParams.get('submodule');
                
                if (initialSubmodule) {
                    showSubModule(initialModule, initialSubmodule);
                } else {
                    const navElement = document.querySelector(`.nav-menu a[onclick*="'${initialModule}'"]`);
                    showModule(initialModule, navElement);
                }
            }
            
            // Show message on load (for success/error from redirects)
            const urlParams = new URLSearchParams(window.location.search);
            const message = urlParams.get('msg');
            const isOtp = urlParams.get('view') === 'otp';
            
            if (message && !isOtp) {
                const isSuccess = message.includes('successful') || message.includes('success');
                const title = isSuccess ? 'Successful Operation' : 'Action Required';
                showCustomActionModal(title, decodeURIComponent(message), 'OK');
            } else if (message && isOtp) {
                const title = 'OTP Required';
                 showCustomActionModal(title, decodeURIComponent(message), 'OK');
            }
        });
    </script>
</body>
</html>
<?php endif; ?>