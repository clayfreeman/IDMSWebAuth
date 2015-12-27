<?php
  class IDMSWebAuth {
    private static function curl_open($url = null) {
      // Initialize a cURL session
      $cURL = curl_init($url);
      // Setup the appropriate cookie handling
      curl_setopt($cURL, CURLOPT_COOKIEFILE, __COOKIES__);
      curl_setopt($cURL, CURLOPT_COOKIEJAR,  __COOKIES__);
      // Return the cURL session
      return $cURL;
    }

    public  static function Phase1($username, $password) {
      // Setup return value
      $retval = array(
        'success' => false
      );

      // Validate username and password
      $username = filter_var($username, FILTER_VALIDATE_EMAIL);
      $password = (strlen($password) != 0 ? $password : false);
      if ($username === false || $password === false)
        throw new Exception('Invalid credentials: could not pre-validate');

      // Open new cURL session for Phase 1
      $cURL = self::curl_open('https://idmsa.apple.com/IDMSWebAuth/'.
        'authenticate');
      // Return both response headers and body
      curl_setopt($cURL, CURLOPT_RETURNTRANSFER, 1);
      curl_setopt($cURL, CURLOPT_HEADER,         1);
      // Setup cURL session POST fields
      curl_setopt($cURL, CURLOPT_POSTFIELDS, http_build_query(array(
        'appIdKey'        => '891bd3417a7776362562d2197f89480a8547b108fd934911'.
                             'bcbea0110d07f757',
        'accNameLocked'   => 'false',
        'language'        => 'US-EN',
        'path'            => '//membercenter/index.action',
        'Env'             => 'PROD',
        'appleId'         => $username,
        'accountPassword' => $password
      )));
      // Execute the cURL session
      $result = curl_exec($cURL);
      curl_close($cURL);

      // Parse cookies from response
      $cookies = array();
      preg_match_all('/^Set-Cookie:\\s*([^;]*)/mi', $result, $matches);
      foreach ($matches[1] as $match) {
        parse_str($match, $cookie);
        $cookies = array_merge($cookies, $cookie);
      }

      // Determine if the 'myacinfo' cookie was provided
      if (isset($cookies['myacinfo']))
        $retval['success'] = true;
      else {
        // Determine if login failed
        $result = \Sunra\PhpSimple\HtmlDomParser::str_get_html($result)->find(
          'form[name=deviceForm]', 0);
        if ($result === NULL)
          throw new Exception('Invalid credentials: wrong username/password');
        else {
          // Fetch 'ctkn' field from two-factor device selection form
          $retval['ctkn']    = $result->find('#ctkn', 0)->value;
          // Fetch device list from two-factor device selection form
          $devices           = $result->find('#devices', 0);
          $retval['devices'] = array();
          // Add each device to the pool of possible two-factor devices
          foreach ($devices->find('.formrow') as $row) {
            // Parse this device's index number
            preg_match('/\\D*(\\d+)$/', $row->find('input', 0)->id, $matches);
            $item = intval($matches[1]);
            // Parse the device name
            $name = trim(html_entity_decode($row->find('label', 0)->plaintext));
            $retval['devices'][$item] = $name;
          }
        }
      }

      // Return the result of Phase 1
      return $retval;
    }

    public  static function Phase2($status, $method) {
      // Setup return value
      $retval = array(
        'success' => false
      );

      // Validate current status
      if (!isset($status['devices'][intval($method)]) ||
          !isset($status['ctkn']))
        throw new Exception('Invalid method chosen or no \'ctkn\' provided');

      // Open new cURL session for Phase 2
      $cURL = self::curl_open('https://idmsa.apple.com/IDMSWebAuth/'.
        'generateSecurityCode');
      // Return both response headers and body
      curl_setopt($cURL, CURLOPT_RETURNTRANSFER, 1);
      curl_setopt($cURL, CURLOPT_HEADER,         1);
      // Setup cURL session POST fields
      curl_setopt($cURL, CURLOPT_POSTFIELDS, http_build_query(array(
        'deviceIndex' => intval($method),
        'ctkn'        => $status['ctkn']
      )));
      // Execute the cURL session
      $result = curl_exec($cURL);
      curl_close($cURL);

      // Determine if a code was generated
      $result = \Sunra\PhpSimple\HtmlDomParser::str_get_html($result)->find(
        'form[name=deviceForm]', 0);
      if ($result === NULL)
        throw new Exception('Invalid \'ctkn\' field provided');
      else {
        // Fetch new 'ctkn' value from the given form
        $retval['ctkn'] = $result->find('#ctkn', 0)->value;
      }

      // Return the result of Phase 2
      return $retval;
    }

    public  static function Phase3($status, $code) {
      // Setup return value
      $retval = array(
        'success' => false
      );

      // Validate current status
      $code = intval($code);
      if ($code <= 0 || $code >= 9999 || !isset($status['ctkn']))
        throw new Exception('Invalid code or no \'ctkn\' provided');

      $code = strval($code);
      while (strlen($code) < 4)
        $code = '0'.$code;

      // Open new cURL session for Phase 2
      $cURL = self::curl_open('https://idmsa.apple.com/IDMSWebAuth/'.
        'validateSecurityCode');
      // Return both response headers and body
      curl_setopt($cURL, CURLOPT_RETURNTRANSFER, 1);
      curl_setopt($cURL, CURLOPT_HEADER,         1);
      // Setup cURL session POST fields
      curl_setopt($cURL, CURLOPT_POSTFIELDS, http_build_query(array(
        'digit1'             => substr($code, 0, 1),
        'digit2'             => substr($code, 1, 1),
        'digit3'             => substr($code, 2, 1),
        'digit4'             => substr($code, 3, 1),
        'ctkn'               => $status['ctkn'],
        'rememberMeSelected' => 'true'
      )));
      // Execute the cURL session
      $result = curl_exec($cURL);
      curl_close($cURL);

      // Parse cookies from response
      $cookies = array();
      preg_match_all('/^Set-Cookie:\\s*([^;]*)/mi', $result, $matches);
      foreach ($matches[1] as $match) {
        parse_str($match, $cookie);
        $cookies = array_merge($cookies, $cookie);
      }

      // Determine if the code was validated
      if (isset($cookies['myacinfo']))
        $retval['success'] = true;

      // Return the result of Phase 2
      return $retval;
    }
  }
