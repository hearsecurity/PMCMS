<?php

$validation = array();
$validation[] = "You have an error in";
$validation[] = 'Warning: mysql_';
$validation[] = 'function.mysql';
$validation[] = 'MySQL result index';
$validation[] = 'MySQL Error';
$validation[] = 'MySQL ODBC';
$validation[] = 'MySQL Driver';
$validation[] = 'mysqli.query';
$validation[] = 'num_rows';
$validation[] = 'mysql error:';
$validation[] = 'supplied argument is not a valid MySQL result resource';
$validation[] = 'on MySQL result index';
$validation[] = 'Error Executing Database Query';
$validation[] = 'mysql_';
$validation[] = 'ORA-00921: unexpected end of SQL command';
$validation[] = 'ORA-01756';
$validation[] = 'ORA-';
$validation[] = 'Oracle ODBC';
$validation[] = 'Oracle Error';
$validation[] = 'Oracle Driver';
$validation[] = 'Oracle DB2';
$validation[] = 'error ORA-';
$validation[] = 'SQL command not properly ended';
$validation[] = 'Microsoft JET Database';
$validation[] = 'ADODB.Recordset';
$validation[] = '500 - Internal server error';
$validation[] = 'Microsoft OLE DB Provider';
$validation[] = 'Unclosed quotes';
$validation[] = 'ADODB.Command';
$validation[] = 'ADODB.Field error';
$validation[] = 'Microsoft VBScript';
$validation[] = 'Microsoft OLE DB Provider for SQL Server';
$validation[] = 'Unclosed quotation mark';
$validation[] = 'Microsoft OLE DB Provider for Oracle';
$validation[] = 'Active Server Pages error';
$validation[] = 'OLE/DB provider returned message';
$validation[] = 'OLE DB Provider for ODBC';
$validation[] = "error '800a0d5d'";
$validation[] = "error '800a000d'";
$validation[] = 'Unclosed quotation mark after the character string';
$validation[] = '[Microsoft][SQL Server Native Client 11.0][SQL Server]';
$validation[] = 'Warning: odbc_';
$validation[] = 'Warning: pg_';
$validation[] = 'PostgreSql Error:';
$validation[] = 'function.pg';
$validation[] = 'Supplied argument is not a valid PostgreSQL result';
$validation[] = 'PostgreSQL query failed: ERROR: parser: parse error';
$validation[] = 'pg_';

function validate($result) {
 
  global $validation;

  foreach ($validation as $error) {
    if (strpos($result, $error) !== FALSE) { // Yoshi version 
        return true;
    }
  }
  return false;
}

function SQL_Checker($sites) {

    $cookie = "cookie.txt";
    $node_count = count($sites);
    $curl_arr = array();
    $vulns = array();
    $master = curl_multi_init();

    for($i = 0; $i < $node_count; $i++)
    {

        $sites[$i] = trim(preg_replace('/\s\s+/', ' ', $sites[$i]));
        $url = $sites[$i] . "'";
        $agent = "Mozilla/5.0 (X11; Linux x86_64; rv:2.2a1pre) Gecko/20110324 Firefox/4.2a1pre"; 
        $curl_arr[$i] = curl_init($url);
        curl_setopt($curl_arr[$i], CURLOPT_USERAGENT, $agent);
        curl_setopt($curl_arr[$i], CURLOPT_RETURNTRANSFER, true);
        curl_setopt($curl_arr[$i], CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($curl_arr[$i], CURLOPT_SSL_VERIFYHOST,false);
        curl_setopt($curl_arr[$i], CURLOPT_SSL_VERIFYPEER,false);
        curl_setopt($curl_arr[$i], CURLOPT_MAXREDIRS, 10);
        curl_setopt($curl_arr[$i], CURLOPT_CONNECTTIMEOUT, 10);
        curl_setopt($curl_arr[$i], CURLOPT_TIMEOUT, 20);
        curl_setopt($curl_arr[$i], CURLOPT_COOKIEJAR, $cookie);
        curl_setopt($curl_arr[$i], CURLOPT_COOKIEFILE, $cookie);
        curl_setopt($curl_arr[$i], CURLOPT_REFERER, $url);

        curl_multi_add_handle($master, $curl_arr[$i]);
    }

    do {
        curl_multi_exec($master,$running);
    } while($running > 0);

    for($i = 0; $i < $node_count; $i++)
    {
        $results[] = curl_multi_getcontent  ( $curl_arr[$i]  );
        $site[] = curl_getinfo  ( $curl_arr[$i]  );
        if(validate($results[$i])) {
          $vulns[] = $site[$i]['url'];
        }
    }

    echo "[*] Vulns: ". count($vulns) . "\n";
    $counter = 0;

    if(count($vulns) != 0) {
        echo "[*] Saving results to vulns.txt\n";
        $fp = fopen('vulns.txt', 'a');
        while($counter < count($vulns)) {
          fwrite($fp, $vulns[$counter] ."\n");
          $counter++;
        }
    }

}


function load_urls() {

  $file = fopen("sites.txt", "r");
  $urls = array();

  while (!feof($file)) {
     $urls[] = fgets($file);
  }
  fclose($file);
  return $urls;
}



function banner() {

  echo "  _   _                 ____                       _ _           \n";
  echo " | | | | ___  __ _ _ __/ ___|  ___  ___ _   _ _ __(_) |_ _   _   \n";
  echo " | |_| |/ _ \/ _` | '__\___ \ / _ \/ __| | | | '__| | __| | | |  \n";
  echo " |  _  |  __/ (_| | |   ___) |  __/ (__| |_| | |  | | |_| |_| |  \n";
  echo " |_| |_|\___|\__,_|_|  |____/ \___|\___|\__,_|_|  |_|\__|\__, |  \n";
  echo "                                                         |___/   ";

    echo "\n-------------------------\n";
    echo "   Author: HearSecurity  \n";
    echo "----------------------------------\n";
    echo "   Tool: Mass SQLI Checker        \n";
    echo "----------------------------------\n";
    echo "   Usage: SQL-Check.php check     \n";
    echo "-----------------------------------\n\n";
}



if($argv[1] == "check") {

    $urls = load_urls();
    echo "\n[*] Loaded: " . count($urls)."\n";
    echo "[*] It may take a few minutes, Please wait...\n\n";
    SQL_Checker($urls);

}else{
    banner();
}

?>
