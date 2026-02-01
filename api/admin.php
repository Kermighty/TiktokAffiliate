<?php
session_start();
header('Content-Type: application/json');

require_once '../config/db.php';

// Check if user is logged in
if (!isset($_SESSION['user_id'])) {
    echo json_encode(['success' => false, 'message' => 'Unauthorized. Please login.']);
    exit;
}

$user_id = $_SESSION['user_id'];
$user_role = $_SESSION['role'] ?? 'user';
$action = $_POST['action'] ?? $_GET['action'] ?? '';

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

// Get Activity Logs (Admin & Manager can access)
if ($action === 'get_logs') {
    // Check permission - both admin and manager can view logs
    if ($user_role !== 'admin' && $user_role !== 'manager') {
        echo json_encode(['success' => false, 'message' => 'Unauthorized. Admin or Manager access required.']);
        exit;
    }

    $limit = intval($_GET['limit'] ?? 100);
    $offset = intval($_GET['offset'] ?? 0);

    try {
        $stmt = $pdo->prepare("
            SELECT al.*, u.username, u.full_name 
            FROM activity_logs al
            LEFT JOIN users u ON al.user_id = u.id
            ORDER BY al.created_at DESC
            LIMIT ? OFFSET ?
        ");
        $stmt->execute([$limit, $offset]);
        $logs = $stmt->fetchAll();

        echo json_encode([
            'success' => true,
            'logs' => $logs
        ]);
    } catch (PDOException $e) {
        echo json_encode(['success' => false, 'message' => 'Failed to fetch logs: ' . $e->getMessage()]);
    }
    exit;
}

// All actions below require ADMIN role only
if ($user_role !== 'admin') {
    echo json_encode(['success' => false, 'message' => 'Unauthorized. Admin access only.']);
    exit;
}

// Get All Users
if ($action === 'get_users') {
    try {
        $stmt = $pdo->query("
            SELECT id, username, email, full_name, role, is_active, created_at, 
                   (SELECT COUNT(*) FROM products WHERE user_id = users.id) as product_count
            FROM users 
            ORDER BY created_at DESC
        ");
        $users = $stmt->fetchAll();

        echo json_encode([
            'success' => true,
            'users' => $users
        ]);
    } catch (PDOException $e) {
        echo json_encode(['success' => false, 'message' => 'Failed to fetch users: ' . $e->getMessage()]);
    }
}

// Update User Role
elseif ($action === 'update_role') {
    $target_user_id = intval($_POST['user_id'] ?? 0);
    $new_role = $_POST['role'] ?? '';

    if ($target_user_id <= 0) {
        echo json_encode(['success' => false, 'message' => 'Invalid user ID']);
        exit;
    }

    if (!in_array($new_role, ['admin', 'manager', 'user'])) {
        echo json_encode(['success' => false, 'message' => 'Invalid role']);
        exit;
    }

    // Prevent changing own role
    if ($target_user_id == $user_id) {
        echo json_encode(['success' => false, 'message' => 'You cannot change your own role']);
        exit;
    }

    try {
        $stmt = $pdo->prepare("UPDATE users SET role = ? WHERE id = ?");
        $stmt->execute([$new_role, $target_user_id]);

        logActivity($pdo, $user_id, 'update_user_role', 'user', $target_user_id, "Changed user role to: $new_role");

        echo json_encode(['success' => true, 'message' => 'User role updated successfully']);
    } catch (PDOException $e) {
        echo json_encode(['success' => false, 'message' => 'Failed to update role: ' . $e->getMessage()]);
    }
}

// Toggle User Active Status
elseif ($action === 'toggle_status') {
    $target_user_id = intval($_POST['user_id'] ?? 0);

    if ($target_user_id <= 0) {
        echo json_encode(['success' => false, 'message' => 'Invalid user ID']);
        exit;
    }

    // Prevent deactivating own account
    if ($target_user_id == $user_id) {
        echo json_encode(['success' => false, 'message' => 'You cannot deactivate your own account']);
        exit;
    }

    try {
        $stmt = $pdo->prepare("UPDATE users SET is_active = NOT is_active WHERE id = ?");
        $stmt->execute([$target_user_id]);

        logActivity($pdo, $user_id, 'toggle_user_status', 'user', $target_user_id, "Toggled user active status");

        echo json_encode(['success' => true, 'message' => 'User status updated successfully']);
    } catch (PDOException $e) {
        echo json_encode(['success' => false, 'message' => 'Failed to update status: ' . $e->getMessage()]);
    }
}

// Delete User
elseif ($action === 'delete_user') {
    $target_user_id = intval($_POST['user_id'] ?? 0);

    if ($target_user_id <= 0) {
        echo json_encode(['success' => false, 'message' => 'Invalid user ID']);
        exit;
    }

    // Prevent deleting own account
    if ($target_user_id == $user_id) {
        echo json_encode(['success' => false, 'message' => 'You cannot delete your own account']);
        exit;
    }

    try {
        $stmt = $pdo->prepare("DELETE FROM users WHERE id = ?");
        $stmt->execute([$target_user_id]);

        logActivity($pdo, $user_id, 'delete_user', 'user', $target_user_id, "Deleted user ID: $target_user_id");

        echo json_encode(['success' => true, 'message' => 'User deleted successfully']);
    } catch (PDOException $e) {
        echo json_encode(['success' => false, 'message' => 'Failed to delete user: ' . $e->getMessage()]);
    }
}

// Get Dashboard Statistics
elseif ($action === 'get_stats') {
    try {
        // Total users
        $stmt = $pdo->query("SELECT COUNT(*) as total FROM users");
        $total_users = $stmt->fetch()['total'];

        // Active users
        $stmt = $pdo->query("SELECT COUNT(*) as total FROM users WHERE is_active = 1");
        $active_users = $stmt->fetch()['total'];

        // Total products
        $stmt = $pdo->query("SELECT COUNT(*) as total FROM products");
        $total_products = $stmt->fetch()['total'];

        // Approved products
        $stmt = $pdo->query("SELECT COUNT(*) as total FROM products WHERE is_approved = 1");
        $approved_products = $stmt->fetch()['total'];

        // Pending products
        $stmt = $pdo->query("SELECT COUNT(*) as total FROM products WHERE is_approved = 0");
        $pending_products = $stmt->fetch()['total'];

        // Users by role
        $stmt = $pdo->query("SELECT role, COUNT(*) as count FROM users GROUP BY role");
        $users_by_role = $stmt->fetchAll();

        // Recent activity
        $stmt = $pdo->query("
            SELECT al.*, u.username 
            FROM activity_logs al
            LEFT JOIN users u ON al.user_id = u.id
            ORDER BY al.created_at DESC
            LIMIT 10
        ");
        $recent_activity = $stmt->fetchAll();

        echo json_encode([
            'success' => true,
            'stats' => [
                'total_users' => $total_users,
                'active_users' => $active_users,
                'total_products' => $total_products,
                'approved_products' => $approved_products,
                'pending_products' => $pending_products,
                'users_by_role' => $users_by_role,
                'recent_activity' => $recent_activity
            ]
        ]);
    } catch (PDOException $e) {
        echo json_encode(['success' => false, 'message' => 'Failed to fetch stats: ' . $e->getMessage()]);
    }
}

else {
    echo json_encode(['success' => false, 'message' => 'Invalid action']);
}