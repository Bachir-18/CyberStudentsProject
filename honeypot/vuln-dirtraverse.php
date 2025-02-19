<?php
// WARNING: This is a simulated vulnerability.
if (isset($_GET['file'])) {
    $file = $_GET['file'];
    // Log the traversal attempt
    error_log("Directory traversal attempt: file parameter = " . $file . " from " . $_SERVER['REMOTE_ADDR']);
    // Instead of reading the actual file, simulate a response:
    echo "File contents of " . htmlspecialchars($file);
} else {
    echo "No file specified.";
}
?>
