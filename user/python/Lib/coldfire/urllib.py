import string

def unquote(s):
    mychr = chr
    myatoi = string.atoi
    list = string.split(s, '%')
    res = [list[0]]
    myappend = res.append
    del list[0]
    for item in list:
        if item[1:2]:
            try:
                myappend(mychr(myatoi(item[:2], 16))
                     + item[2:])
            except:
                myappend('%' + item)
        else:
            myappend('%' + item)
    return string.join(res, "")
