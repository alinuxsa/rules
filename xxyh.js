let data = JSON.parse($response.body);
data.vip_state = 2;
data.vip_valid_till_date = "永不过期";
delete data.vip_expired_date_num;
$done({body: JSON.stringify(data)});
