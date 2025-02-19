<?php
// Start logging
date_default_timezone_set('UTC');
$log_file = "/var/log/honeypot/upload_attempts.log";

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['file'])) {
    $ip = $_SERVER['HTTP_X_REAL_IP'] ?? $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'];
    $file_name  = $_FILES['file']['name'];
    $file_type  = $_FILES['file']['type'];
    $file_size  = $_FILES['file']['size'];
    $user_agent = $_SERVER['HTTP_USER_AGENT'];
    $email      = filter_var($_POST['email'], FILTER_SANITIZE_EMAIL);
    $message    = htmlspecialchars($_POST['message'] ?? 'No message');

    // Log the attack attempt
    $log_entry = sprintf("[%s] Upload Attempt - IP: %s | Email: %s | File: %s | Type: %s | Size: %d bytes | User-Agent: %s | Message: %s\n",
        date('Y-m-d H:i:s'), $ip, $email, $file_name, $file_type, $file_size, $user_agent, $message);
    file_put_contents($log_file, $log_entry, FILE_APPEND);

    // Pretend the file was uploaded successfully
    echo "<p style='color:green; font-weight: bold;'>Your file has been successfully uploaded. Our team will contact you at <strong>$email</strong> soon.</p>";

    // But actually, discard it (do not save)
    exit();
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Contact Form</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f4f4f4;
            text-align: center;
            padding: 50px;
        }
        .container {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0px 0px 10px 0px rgba(0, 0, 0, 0.1);
            max-width: 400px;
            margin: auto;
        }
        input, textarea {
            width: 100%;
            padding: 10px;
            margin: 10px 0;
            border: 1px solid #ccc;
            border-radius: 4px;
        }
        button {
            background: #28a745;
            color: white;
            padding: 10px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 16px;
        }
        button:hover {
            background: #218838;
        }
    </style>
</head>
<body>

    <div class="container">
        <h2>Contact Us</h2>
        <p>Upload your file, enter your email, and leave a message. Our team will get back to you soon.</p>
        
        <form method="POST" enctype="multipart/form-data">
            <input type="email" name="email" placeholder="Enter your email" required>
            <input type="file" name="file" required>
            <textarea name="message" placeholder="Enter your message..." required></textarea>
            <button type="submit">Submit</button>
        </form>
    </div>

</body>
</html>

