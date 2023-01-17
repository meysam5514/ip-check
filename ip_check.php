<?php
error_reporting(false);
header('Content-type: application/json;');

$typekobs = $_GET['ip'];

$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, "https://scamalytics.com/ip/$typekobs");
//curl_setopt($ch, CURLOPT_POST, true);
//curl_setopt($ch, CURLOPT_POSTFIELDS,$data);
curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
//curl_setopt($ch, CURLOPT_COOKIEJAR,"cooki.txt");
//curl_setopt($ch, CURLOPT_COOKIEFILE, "cooki.txt");
//curl_setopt($ch, CURLOPT_USERAGENT, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.130 Safari/537.36");
$meysam1= curl_exec($ch);
curl_close($ch);


preg_match_all('#"ip":"(.*?)",#',$meysam1,$sidepath1);
preg_match_all('#"score":"(.*?)",#',$meysam1,$sidepath2);
preg_match_all('#"risk":"(.*?)"#',$meysam1,$sidepath3);
preg_match_all('#<td>(.*?)</td>#',$meysam1,$sidepath4);
preg_match_all('#<td><div class="risk (.*?)">(.*?)</div></td>#',$meysam1,$sidepath5);
preg_match_all('#<td><div class="protocol_status"><div class="(.*?)">(.*?)</div><div class="product"></div></div></td>#',$meysam1,$sidepath6);
preg_match_all('#<td><a href="(.*?)">(.*?)</a></td>#',$meysam1,$sidepath7);
preg_match_all('#<td colspan="2" class="colspan">(.*?)</td>#',$meysam1,$sidepath8);

$ip=$sidepath1[1][0];
$score=$sidepath2[1][0];
$risk=$sidepath3[1][0];
$Hostname=$sidepath4[1][0];
$ASN=$sidepath4[1][1];
$ISP_Name=$sidepath7[2][0];
$ISP_link=$sidepath7[1][0];
$Organization_Name=$sidepath4[1][3];
$Connection_type=$sidepath4[1][4];
$Country_Name=$sidepath4[1][5];
$Country_Code=$sidepath4[1][6];
$Region=$sidepath4[1][7];
$City=$sidepath4[1][8];
$Postal_Code=$sidepath4[1][9];
$Metro_Code=$sidepath4[1][10];
$Area_Code=$sidepath4[1][11];
$Latitude=$sidepath4[1][12];
$Longitude=$sidepath4[1][13];
$Anonymizing_VPN=$sidepath5[2][0];
$Tor_Exit_Node=$sidepath5[2][1];
$Server=$sidepath5[2][2];
$Public_Proxy=$sidepath5[2][3];
$Web_Proxy=$sidepath5[2][4];
$Search_Engine_Robot=$sidepath5[2][5];
$HTTP=$sidepath6[2][0];
$SSL=$sidepath6[2][1];
$HTTP_PROXY=$sidepath6[2][2];
$OPSMESSAGING=$sidepath6[2][3];
$TOR_ORPORT=$sidepath6[2][4];
$TCP=$sidepath6[2][5];
$SSH=$sidepath6[2][6];

$resultarz = array();   
$resultarz['IP Fraud Risk API']['ip']=$ip;  
$resultarz['IP Fraud Risk API']['score(0-100)']=$score;  
$resultarz['IP Fraud Risk API']['risk']=$risk;  

$resultarz['Operator']['Hostname']=$Hostname;  
$resultarz['Operator']['ASN']=$ASN;  
$resultarz['Operator']['ISP Name']=$ISP_Name;  
$resultarz['Operator']['ISP Link']=$ISP_link;  
$resultarz['Operator']['Organization Name']=$Organization_Name;  
$resultarz['Operator']['Connection type']=$Connection_type;

$resultarz['Location']['Country Name']=$Country_Name;  
$resultarz['Location']['Country Code']=$Country_Code;  
$resultarz['Location']['Region']=$Region;  
$resultarz['Location']['City']=$City;  
$resultarz['Location']['Postal Code']=$Postal_Code;  
$resultarz['Location']['Metro Code']=$Metro_Code;  
$resultarz['Location']['Area Code']=$Area_Code;  
$resultarz['Location']['Latitude']=$Latitude;  
$resultarz['Location']['Longitude']=$Longitude;  
$resultarz['Port Scan']['HTTP(80/http)']=$HTTP;  
$resultarz['Port Scan']['SSL(443/ssl/http)']=$SSL;  
$resultarz['Port Scan']['HTTP-PROXY(8080/http-proxy)']=$HTTP_PROXY;  
$resultarz['Port Scan']['OPSMESSAGING(8090/opsmessaging)']=$OPSMESSAGING;  
$resultarz['Port Scan']['TOR-ORPORT(9001/tor-orport)']=$TOR_ORPORT;  
$resultarz['Port Scan']['TCP(9030/tcp/udp)']=$TCP;  
$resultarz['Port Scan']['SSH(22/ssh)']=$SSH;  
$resultarz['Proxies']['Anonymizing VPN']=$Anonymizing_VPN;  
$resultarz['Proxies']['Tor Exit Node']=$Tor_Exit_Node;  
$resultarz['Proxies']['Server']=$Server;  
$resultarz['Proxies']['Public Proxy']=$Public_Proxy;  
$resultarz['Proxies']['Web Proxy']=$Web_Proxy;  
$resultarz['Proxies']['Search Engine Robot']=$Search_Engine_Robot;  

$resultarz['Domain ']=$sidepath8[1];  

//=========================================================
echo json_encode(['ok' => true, 'channel' => '@SIDEPATH','writer' => '@meysam_s71',  'Results' =>$resultarz], 448);
//=========================================================




