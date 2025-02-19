<?php
// Redirect all login attempts to the honeypot
header("Location: http://wonderful-stuff.store/wp-login.php");
exit();
?>
