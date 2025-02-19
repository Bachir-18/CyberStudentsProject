<?php
/*
Plugin Name: WP Debug RCE
Description: Debugging tool for admins (vulnerable to RCE).
Version: 1.0
Author: Admin
*/

// Create an "Admin Debug Console" in WordPress Dashboard
add_action('admin_menu', function() {
add_menu_page('Debug Console', 'Debug Console', 'edit_posts', 'wp-debug-rce', 'debug_console_page');

});

// Fake RCE Functionality
function debug_console_page() {
    echo '<h2>System Debug Console</h2>';

    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['cmd'])) {
        $command = $_POST['cmd'];
        $attacker_ip = $_SERVER['REMOTE_ADDR'];

        // Log the attack attempt
        file_put_contents("/var/log/honeypot/fake_plugin_rce.log", 
            "[Fake Plugin RCE] IP: $attacker_ip | Command: $command\n", FILE_APPEND);

        // Send the command to admin-console.php and get the response
        $output = file_get_contents("http://wonderful-stuff.store/admin-console.php?cmd=" . urlencode($command));

        // Display the fake command output
        echo '<h3>Command Output:</h3>';
        echo '<pre>' . htmlspecialchars($output) . '</pre>';
    }

    echo '<form method="POST">';
    echo '<p>Enter System Command:</p>';
    echo '<input type="text" name="cmd">';
    echo '<button type="submit">Run</button>';
    echo '</form>';
}

add_filter('all_plugins', function($plugins) {
    unset($plugins['wp-debug-rce/wp-debug-rce.php']); // Hide from the plugins list
    return $plugins;
});

?>
