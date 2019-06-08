with open ('stageX.bin','wb') as f:
    f.write(b'\xcc'*100)
#>>> print(repr(bytes("\xcc",'utf-8')))
#b'\xc3\x8c'
