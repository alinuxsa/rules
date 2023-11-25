function operator(proxies) {
  return proxies.map(p => {
    if (p.type == "vmess" && Object.keys(p['ws-opts']).length > 0) {
      let wspath = p['ws-opts'].path;
      wspath = wspath.replace("?ed=2048", "");
      p['ws-opts'].path = wspath;
      return p;
    }
  });
}
