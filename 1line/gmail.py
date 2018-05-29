#
# Made by staticvoid
# http://ubuntuforums.org/showthread.php?t=631157
#

#!/env/python
import os
import string

#Enter your username and password below within double quotes
# eg. username="username" and password="password"
username="username"
password="password"

com="wget -O - https://"+username+":"+password+"@mail.google.com/mail/feed/atom --no-check-certificate"

temp=os.popen(com)
msg=temp.read()
index=string.find(msg,"<fullcount>")
index2=string.find(msg,"</fullcount>")
fc=int(msg[index+11:index2])

if fc==0:
   print "0"
else:
   print str(fc)+""
