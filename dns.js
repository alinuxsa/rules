const SSID = $network.wifi.ssid;
const gw = $network.v4.primaryRouter;

if ( gw === '192.168.31.1'&& SSID === 'ChinaNet-K3i6' ){
    $done({address: '192.168.31.84', ttl: 600});
} else {
    $httpClient.get('http://119.29.29.29/d?dn=' + $argument, function(error, response, data){
  if (error) {
    $done({}); // Fallback to standard DND query
  } else {
    $done({addresses: data.split(';'), ttl: 600});
  }
});
};
