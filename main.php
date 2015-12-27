<?php
  // Load the required packages from composer
  require_once(__DIR__.'/vendor/autoload.php');

  // Load the IDMSWebAuth class
  require_once(__DIR__.'/include/IDMSWebAuth.php');

  // Define a global cookie file for authentication
  define('__COOKIES__', __DIR__.'/cookies.txt');

  // Query user for Apple ID and password
  $username = readline("Apple ID: ");
  $password = readline("Password: ");
  echo "\n";

  // Perform Phase 1 of authentication
  $status = IDMSWebAuth::Phase1($username, $password);

  // Check if authentication succeeded
  if ($status['success'] == true)
    die("Authentication successful\n");
  else {
    // This account requires two-factor authentication
    echo "Two-Factor Authentication Methods:\n";
    foreach ($status['devices'] as $index => $name)
      echo ' ['.$index.']: '.$name."\n";
    $method = intval(readline("\nSelect an authentication method: "));
    // Proceed to Phase 2 of authentication
    $status = IDMSWebAuth::Phase2($status, $method);
    // Query for an authentication code
    $code   = intval(readline("Authentication code: "));
    echo "\n";
    // Proceed to Phase 3 of authentication
    $status = IDMSWebAuth::Phase3($status, $code);
    if ($status['success'] == true)
      die("Authentication successful\n");
    else
      die("Authentication failed\n");
  }
