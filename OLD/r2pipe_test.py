
import r2pipe
r2p=r2pipe.open()  # open without arguments only for #!pipe
r2p.cmd('aa;aac')  # analyze all symbols and callsfor a in r2p.cmdj('aflj'):
for a in r2p.cmdj('aflj'):
  if a['size'] > 128:
    print('[+] Function '+a['name'])
    print(r2p.cmd('pif@'+str(a['offset'])+'~call'))
