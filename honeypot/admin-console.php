<?php
session_start(); // Track attacker's session

$real_ip = $_SERVER['HTTP_X_REAL_IP'] ?? $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'];

// Log attack attempt
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['cmd'])) {
    $command = trim($_GET['cmd']);

    file_put_contents("/var/log/honeypot/shell.log", 
        "[RCE] IP: $real_ip | Command: $command\n", FILE_APPEND);

    // Add a fake delay to make it look real
    sleep(rand(1, 3));

    // Switch to Geek's restricted shell and execute the command
    $output = shell_exec("echo '12345' | su Geek  && $command");

    // Return output in plain text
    header("Content-Type: text/plain");
    echo $output;
    exit();
}
?>
