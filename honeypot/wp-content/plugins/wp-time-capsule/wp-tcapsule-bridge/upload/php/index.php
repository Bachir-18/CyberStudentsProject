<?php
// Log the upload attempt
file_put_contents('/var/log/honeypot/wp-time-capsule.log', "Upload attempt from: " . $_SERVER['REMOTE_ADDR'] . " at " . date('Y-m-d H:i:s') . "\n", FILE_APPEND);

// Fake success response
echo json_encode(['status' => 'success', 'message' => 'File uploaded successfully.']);
?>
