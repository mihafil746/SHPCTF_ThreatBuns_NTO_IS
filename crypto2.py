import requests

n = 164120438830096022578174522187029756905595170255244112941199875588197300851073195492615317837527195708874307286334494082844769384417967370474062105756435191758111630983818435926496449101606840998845985119437040166531152445040127049185892530772437871145884938821323412578447601782475959448699097133541934104123
url = 'http://10.10.23.10:1177/'
i = 0
s = ''
print(requests.get(url).text)
r = requests.get(url + 'guess_bit?bit=' + str(i))
#print(r.text)
while 'overflow' not in r.text:
    #print('here')
    f = True
    for j in range(30):
        r = requests.get(url + 'guess_bit?bit=' + str(i))
        t = r.text.split('"')[2][1:-2]
        if int(t) < n // 2:
            f = False
            break

    #print(t)
    if f == True:
        s += '0'
    else:
        s += '1'
    print(s)
    i += 1
print(s)
