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

// Helper function to check permissions
function hasPermission($role, $permission) {
    $permissions = [
        'admin' => ['create', 'read', 'update', 'delete', 'approve', 'view_all', 'manage_users'],
        'manager' => ['create', 'read', 'update', 'delete', 'approve', 'view_all'],
        'user' => ['create', 'read', 'update', 'delete']
    ];
    
    return in_array($permission, $permissions[$role] ?? []);
}

// Create Product
if ($action === 'create') {
    if (!hasPermission($user_role, 'create')) {
        echo json_encode(['success' => false, 'message' => 'You do not have permission to create products']);
        exit;
    }

    $product_name = trim($_POST['product_name'] ?? '');
    $category = trim($_POST['category'] ?? '');
    $price = floatval($_POST['price'] ?? 0);
    $commission_rate = floatval($_POST['commission_rate'] ?? 0);
    $quality_rating = intval($_POST['quality_rating'] ?? 0);

    // Validation
    if (empty($product_name) || empty($category)) {
        echo json_encode(['success' => false, 'message' => 'Product name and category are required']);
        exit;
    }

    if ($price <= 0) {
        echo json_encode(['success' => false, 'message' => 'Price must be greater than 0']);
        exit;
    }

    if ($commission_rate < 0 || $commission_rate > 100) {
        echo json_encode(['success' => false, 'message' => 'Commission rate must be between 0 and 100']);
        exit;
    }

    if ($quality_rating < 1 || $quality_rating > 5) {
        echo json_encode(['success' => false, 'message' => 'Quality rating must be between 1 and 5']);
        exit;
    }

    // Calculate metrics
    $profit_per_sale = ($price * $commission_rate) / 100;
    $quality_score = ($quality_rating / 5) * 60;
    $commission_score = ($commission_rate / 100) * 40;
    $score = round($quality_score + $commission_score);

    // Determine recommendation
    if ($score >= 70) {
        $recommendation = 'PROMOTE';
    } elseif ($score >= 50) {
        $recommendation = 'CONSIDER';
    } else {
        $recommendation = 'SKIP';
    }

    // Auto-approve for admin and manager
    $is_approved = ($user_role === 'admin' || $user_role === 'manager') ? 1 : 0;
    $approved_by = $is_approved ? $user_id : null;

    try {
        $stmt = $pdo->prepare("
            INSERT INTO products (user_id, product_name, category, price, commission_rate, quality_rating, profit_per_sale, score, recommendation, is_approved, approved_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ");
        $stmt->execute([$user_id, $product_name, $category, $price, $commission_rate, $quality_rating, $profit_per_sale, $score, $recommendation, $is_approved, $approved_by]);

        $product_id = $pdo->lastInsertId();
        logActivity($pdo, $user_id, 'create_product', 'product', $product_id, "Created product: $product_name");

        echo json_encode([
            'success' => true,
            'message' => 'Product added successfully' . (!$is_approved ? ' (Pending approval)' : ''),
            'product_id' => $product_id
        ]);
    } catch (PDOException $e) {
        echo json_encode(['success' => false, 'message' => 'Failed to add product: ' . $e->getMessage()]);
    }
}

// Read All Products
elseif ($action === 'read') {
    if (!hasPermission($user_role, 'read')) {
        echo json_encode(['success' => false, 'message' => 'You do not have permission to view products']);
        exit;
    }

    try {
        // Admin and Manager can see all products, Users only see their own
        if (hasPermission($user_role, 'view_all')) {
            $stmt = $pdo->prepare("
                SELECT p.*, u.username as creator_username, u.full_name as creator_name,
                       approver.username as approver_username
                FROM products p
                LEFT JOIN users u ON p.user_id = u.id
                LEFT JOIN users approver ON p.approved_by = approver.id
                ORDER BY p.created_at DESC
            ");
            $stmt->execute();
        } else {
            $stmt = $pdo->prepare("
                SELECT p.*, u.username as creator_username, u.full_name as creator_name,
                       approver.username as approver_username
                FROM products p
                LEFT JOIN users u ON p.user_id = u.id
                LEFT JOIN users approver ON p.approved_by = approver.id
                WHERE p.user_id = ?
                ORDER BY p.created_at DESC
            ");
            $stmt->execute([$user_id]);
        }
        
        $products = $stmt->fetchAll();

        echo json_encode([
            'success' => true,
            'products' => $products,
            'user_role' => $user_role
        ]);
    } catch (PDOException $e) {
        echo json_encode(['success' => false, 'message' => 'Failed to fetch products: ' . $e->getMessage()]);
    }
}

// Delete Product
elseif ($action === 'delete') {
    if (!hasPermission($user_role, 'delete')) {
        echo json_encode(['success' => false, 'message' => 'You do not have permission to delete products']);
        exit;
    }

    $product_id = intval($_POST['product_id'] ?? 0);

    if ($product_id <= 0) {
        echo json_encode(['success' => false, 'message' => 'Invalid product ID']);
        exit;
    }

    try {
        // Admin can delete any product, others only their own
        if ($user_role === 'admin') {
            $stmt = $pdo->prepare("DELETE FROM products WHERE id = ?");
            $stmt->execute([$product_id]);
        } else {
            $stmt = $pdo->prepare("DELETE FROM products WHERE id = ? AND user_id = ?");
            $stmt->execute([$product_id, $user_id]);
        }

        if ($stmt->rowCount() > 0) {
            logActivity($pdo, $user_id, 'delete_product', 'product', $product_id, "Deleted product ID: $product_id");
            echo json_encode(['success' => true, 'message' => 'Product deleted successfully']);
        } else {
            echo json_encode(['success' => false, 'message' => 'Product not found or unauthorized']);
        }
    } catch (PDOException $e) {
        echo json_encode(['success' => false, 'message' => 'Failed to delete product: ' . $e->getMessage()]);
    }
}

// Update Product
elseif ($action === 'update') {
    if (!hasPermission($user_role, 'update')) {
        echo json_encode(['success' => false, 'message' => 'You do not have permission to update products']);
        exit;
    }

    $product_id = intval($_POST['product_id'] ?? 0);
    $product_name = trim($_POST['product_name'] ?? '');
    $category = trim($_POST['category'] ?? '');
    $price = floatval($_POST['price'] ?? 0);
    $commission_rate = floatval($_POST['commission_rate'] ?? 0);
    $quality_rating = intval($_POST['quality_rating'] ?? 0);

    if ($product_id <= 0) {
        echo json_encode(['success' => false, 'message' => 'Invalid product ID']);
        exit;
    }

    // Calculate metrics
    $profit_per_sale = ($price * $commission_rate) / 100;
    $quality_score = ($quality_rating / 5) * 60;
    $commission_score = ($commission_rate / 100) * 40;
    $score = round($quality_score + $commission_score);

    if ($score >= 70) {
        $recommendation = 'PROMOTE';
    } elseif ($score >= 50) {
        $recommendation = 'CONSIDER';
    } else {
        $recommendation = 'SKIP';
    }

    try {
        // Admin can update any product, others only their own
        if ($user_role === 'admin') {
            $stmt = $pdo->prepare("
                UPDATE products 
                SET product_name = ?, category = ?, price = ?, commission_rate = ?, 
                    quality_rating = ?, profit_per_sale = ?, score = ?, recommendation = ?
                WHERE id = ?
            ");
            $stmt->execute([$product_name, $category, $price, $commission_rate, $quality_rating, $profit_per_sale, $score, $recommendation, $product_id]);
        } else {
            $stmt = $pdo->prepare("
                UPDATE products 
                SET product_name = ?, category = ?, price = ?, commission_rate = ?, 
                    quality_rating = ?, profit_per_sale = ?, score = ?, recommendation = ?
                WHERE id = ? AND user_id = ?
            ");
            $stmt->execute([$product_name, $category, $price, $commission_rate, $quality_rating, $profit_per_sale, $score, $recommendation, $product_id, $user_id]);
        }

        if ($stmt->rowCount() > 0) {
            logActivity($pdo, $user_id, 'update_product', 'product', $product_id, "Updated product: $product_name");
            echo json_encode(['success' => true, 'message' => 'Product updated successfully']);
        } else {
            echo json_encode(['success' => false, 'message' => 'Product not found or no changes made']);
        }
    } catch (PDOException $e) {
        echo json_encode(['success' => false, 'message' => 'Failed to update product: ' . $e->getMessage()]);
    }
}

// Approve Product (Manager and Admin only)
elseif ($action === 'approve') {
    if (!hasPermission($user_role, 'approve')) {
        echo json_encode(['success' => false, 'message' => 'You do not have permission to approve products']);
        exit;
    }

    $product_id = intval($_POST['product_id'] ?? 0);

    if ($product_id <= 0) {
        echo json_encode(['success' => false, 'message' => 'Invalid product ID']);
        exit;
    }

    try {
        $stmt = $pdo->prepare("UPDATE products SET is_approved = 1, approved_by = ? WHERE id = ?");
        $stmt->execute([$user_id, $product_id]);

        if ($stmt->rowCount() > 0) {
            logActivity($pdo, $user_id, 'approve_product', 'product', $product_id, "Approved product ID: $product_id");
            echo json_encode(['success' => true, 'message' => 'Product approved successfully']);
        } else {
            echo json_encode(['success' => false, 'message' => 'Product not found']);
        }
    } catch (PDOException $e) {
        echo json_encode(['success' => false, 'message' => 'Failed to approve product: ' . $e->getMessage()]);
    }
}

// Reject/Unapprove Product (Manager and Admin only)
elseif ($action === 'unapprove') {
    if (!hasPermission($user_role, 'approve')) {
        echo json_encode(['success' => false, 'message' => 'You do not have permission to unapprove products']);
        exit;
    }

    $product_id = intval($_POST['product_id'] ?? 0);

    if ($product_id <= 0) {
        echo json_encode(['success' => false, 'message' => 'Invalid product ID']);
        exit;
    }

    try {
        $stmt = $pdo->prepare("UPDATE products SET is_approved = 0, approved_by = NULL WHERE id = ?");
        $stmt->execute([$product_id]);

        if ($stmt->rowCount() > 0) {
            logActivity($pdo, $user_id, 'unapprove_product', 'product', $product_id, "Unapproved product ID: $product_id");
            echo json_encode(['success' => true, 'message' => 'Product approval removed']);
        } else {
            echo json_encode(['success' => false, 'message' => 'Product not found']);
        }
    } catch (PDOException $e) {
        echo json_encode(['success' => false, 'message' => 'Failed to unapprove product: ' . $e->getMessage()]);
    }
}

else {
    echo json_encode(['success' => false, 'message' => 'Invalid action']);
}