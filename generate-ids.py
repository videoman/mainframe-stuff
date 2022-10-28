
import sys

prefix = sys.argv[1]

int1 = range(0,100000)

userfile = open(prefix + '-usernames.txt', 'a')

for uint in int1:
    uint = str(uint).zfill(5)
    print(prefix + uint, file=userfile)



