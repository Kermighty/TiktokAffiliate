<?php
session_start();
header('Content-Type: application/json');

require_once '../config/db.php';

$action = $_POST['action'] ?? '';

// Helper function to log activity
function logActivity($pdo, $user_id, $action, $target_type = null, $target_id = null, $description = null) {
    try {
        $ip_address = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        $stmt = $pdo->prepare("INSERT INTO activity_logs (user_id, action, target_type, target_id, description, ip_address) VALUES (?, ?, ?, ?, ?, ?)");
        $stmt->execute([$user_id, $action, $target_type, $target_id, $description, $ip_address]);
    } catch (PDOException $e) {
        // Silent fail for logging
    }
}

// Login Handler
if ($action === 'login') {
    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';

    if (empty($username) || empty($password)) {
        echo json_encode(['success' => false, 'message' => 'Username and password are required']);
        exit;
    }

    try {
        $stmt = $pdo->prepare("SELECT id, username, password, full_name, role, is_active FROM users WHERE username = ?");
        $stmt->execute([$username]);
        $user = $stmt->fetch();

        if ($user && password_verify($password, $user['password'])) {
            if (!$user['is_active']) {
                echo json_encode(['success' => false, 'message' => 'Your account has been deactivated. Contact administrator.']);
                exit;
            }

            $_SESSION['user_id'] = $user['id'];
            $_SESSION['username'] = $user['username'];
            $_SESSION['full_name'] = $user['full_name'];
            $_SESSION['role'] = $user['role'];
            
            logActivity($pdo, $user['id'], 'login', null, null, 'User logged in successfully');

            echo json_encode([
                'success' => true,
                'message' => 'Login successful',
                'user' => [
                    'id' => $user['id'],
                    'username' => $user['username'],
                    'full_name' => $user['full_name'],
                    'role' => $user['role']
                ]
            ]);
        } else {
            echo json_encode(['success' => false, 'message' => 'Invalid username or password']);
        }
    } catch (PDOException $e) {
        echo json_encode(['success' => false, 'message' => 'Database error: ' . $e->getMessage()]);
    }
}

// Register Handler
elseif ($action === 'register') {
    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';
    $email = trim($_POST['email'] ?? '');
    $full_name = trim($_POST['full_name'] ?? '');

    // Validation
    if (empty($username) || empty($password) || empty($email) || empty($full_name)) {
        echo json_encode(['success' => false, 'message' => 'All fields are required']);
        exit;
    }

    if (strlen($username) < 3) {
        echo json_encode(['success' => false, 'message' => 'Username must be at least 3 characters']);
        exit;
    }

    if (strlen($password) < 6) {
        echo json_encode(['success' => false, 'message' => 'Password must be at least 6 characters']);
        exit;
    }

    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        echo json_encode(['success' => false, 'message' => 'Invalid email format']);
        exit;
    }

    try {
        // Check if username exists
        $stmt = $pdo->prepare("SELECT id FROM users WHERE username = ?");
        $stmt->execute([$username]);
        if ($stmt->fetch()) {
            echo json_encode(['success' => false, 'message' => 'Username already exists']);
            exit;
        }

        // Check if email exists
        $stmt = $pdo->prepare("SELECT id FROM users WHERE email = ?");
        $stmt->execute([$email]);
        if ($stmt->fetch()) {
            echo json_encode(['success' => false, 'message' => 'Email already registered']);
            exit;
        }

        // Hash password and insert user (default role is 'user')
        $hashed_password = password_hash($password, PASSWORD_DEFAULT);
        $stmt = $pdo->prepare("INSERT INTO users (username, password, email, full_name, role) VALUES (?, ?, ?, ?, 'user')");
        $stmt->execute([$username, $hashed_password, $email, $full_name]);

        echo json_encode(['success' => true, 'message' => 'Registration successful! Please login.']);
    } catch (PDOException $e) {
        echo json_encode(['success' => false, 'message' => 'Registration failed: ' . $e->getMessage()]);
    }
}

// Logout Handler
elseif ($action === 'logout') {
    if (isset($_SESSION['user_id'])) {
        logActivity($pdo, $_SESSION['user_id'], 'logout', null, null, 'User logged out');
    }
    session_destroy();
    echo json_encode(['success' => true, 'message' => 'Logged out successfully']);
}

// Check Session
elseif ($action === 'check_session') {
    if (isset($_SESSION['user_id'])) {
        echo json_encode([
            'success' => true,
            'logged_in' => true,
            'user' => [
                'id' => $_SESSION['user_id'],
                'username' => $_SESSION['username'],
                'full_name' => $_SESSION['full_name'],
                'role' => $_SESSION['role']
            ]
        ]);
    } else {
        echo json_encode(['success' => true, 'logged_in' => false]);
    }
}

else {
    echo json_encode(['success' => false, 'message' => 'Invalid action']);
}