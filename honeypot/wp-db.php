<?php
// WARNING: This code is intentionally vulnerable for honeypot purposes.

// Connect to the fake database (Students_db) using dummy credentials.
$conn = new mysqli("localhost", "john", "password123", "Students_db");
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Retrieve the 'id' parameter from the URL without sanitization.
$id = $_GET['id'];

// Construct the SQL query using unsanitized input (vulnerable to SQL injection).
$query = "SELECT * FROM students WHERE id = '$id'";

// Log the attempted query along with the attacker's IP address.
error_log("SQLi attempt: $query from " . $_SERVER['REMOTE_ADDR']);

// Execute the query.
$result = $conn->query($query);

if ($result) {
    // For each row in the result, display the student's details.
    while ($row = $result->fetch_assoc()) {
        echo "Student: " . htmlspecialchars($row['first_name']) . " " .
             htmlspecialchars($row['last_name']) . " (Username: " .
             htmlspecialchars($row['username']) . ")<br>";
    }
} else {
    echo "No results.";
}

// Close the connection.
$conn->close();
?>
