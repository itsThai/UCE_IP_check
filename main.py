import subprocess
import time
import os
import requests
import base64
import csv
import ipaddress
import re
import imgkit
import json
import dateutil.parser
from requests.exceptions import ConnectionError
from datetime import datetime, timezone, date
from dateutil import parser
from bs4 import BeautifulSoup

#how long between each check
INTERVAL = 86400
exitFlag = 0


ip_regex = r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
path_wkthmltoimage = r'C:\Program Files\wkhtmltopdf\bin\wkhtmltoimage.exe'
config = imgkit.config(wkhtmltoimage=path_wkthmltoimage)
options = {'enable-local-file-access': ""}

PATH_REASON = 'Proof/'
PATH_VPN_Connect = 'C:\Program Files\OpenVPN Connect'

FILE_VPN_List = 'VPN_list.csv'
FILE_VPN_Config = 'new_VPN.ovpn'
FILE_UCE_List = 'UCE_list.txt'
FILE_Listed_IP = 'appeared.txt'
FILE_Log = 'log.txt'
FILE_Reason = 'reason.csv'
FILE_IP_List = 'ip_range.txt'

Public_IP_Check_Link =  'https://ifconfig.me/ip'
UCE_List_Link = 'http://67.58.96.162/rbldnsd-all/dnsbl-1.uceprotect.net.gz'
UCE_Check_Link = 'http://www.uceprotect.net/en/rblcheck.php?'
VPNGate_Link = 'https://www.vpngate.net/api/iphone/'
        

# return the number of line in a file
def count_lines(filename):
    with open(filename, 'r', encoding='cp1252') as f:
        x = len(f.readlines())
        return x


# get content from an url and write it to a file
def call_api(filename, url):
    r = requests.get(url)
    with open(filename, 'wb') as f:
        f.write(r.content)


# check if an IP of VPNT is listed in UCE_list, write listed IPs to a file 
def check_ip():
    print("Checking IP addresses!")
    call_api(FILE_UCE_List, UCE_List_Link)
    open(FILE_Listed_IP, 'w')
    # IP list starts in line 49
    delete_n_first_lines(FILE_UCE_List, 48)
    with open(FILE_UCE_List, "r") as _uce_list:
        for line in _uce_list.readlines():
            _ipAddress = line.strip()
            if check_ip_vip(_ipAddress):
                with open(FILE_Listed_IP, 'a') as appeared:
                    appeared.write("%s\n"%_ipAddress)
    
    if not os.path.exists(FILE_Log):
        open(FILE_Log, 'w')
    
    with open(FILE_Log, 'a+') as f1:
        f1.write('\n-- ' + str(date.today()) + ' has %s'%count_lines(FILE_Listed_IP) + ' IPs got listed --\n')
        f2 = open(FILE_Listed_IP, 'r')
        f1.write(f2.read())
        f1.write("\n")
        
    print("Finish!")


# generate image from html string
def html_to_img(content, ip):
    try:
        jpg_location = os.path.join(PATH_REASON + '%s'%str(date.today()), '%s.jpg'%ip)
        
        # format these html string to .jpg
        imgkit.from_string(content, jpg_location, config=config, options=options)
    except Exception as e:
        _expc_tmp = e
        pass


# Check syntax of IP address
def is_ip(_string):
	_result = re.match(ip_regex, _string)
	return _result


# Check if IP address is belonged to VNPT Static IP range
def check_ip_vip(_ip):
    with open(FILE_IP_List, 'r') as f:
        lines = f.readlines()
        _result = False
        for _line in lines:
            _ip_range = _line.strip()
            _result = ipaddress.ip_address(_ip) in ipaddress.ip_network(_ip_range)
            if _result:
                break
        return _result


# create a VPN config
def create_VPN(counter):
    _filepath = os.path.join(PATH_VPN_Connect, FILE_VPN_Config)
    with open(FILE_VPN_List, 'r', encoding="utf8") as f:
        _csv_reader = csv.reader(f)
        line_count = 0
        for row in _csv_reader:
            if line_count == counter:
                # row[14] is base64-decoded VPN config file
                _cell = row[14]
                _final = base64.b64decode('%s' %_cell)
                # decode and delete all un-wanted characters
                _final = '%s'%_final
                _final = _final.replace('b"' , '').replace('\\r' , '\r').replace('\\n' , '\n')
                with open(_filepath, 'w') as o:
                    o.write('%s'%_final)
            line_count += 1


# return time in Y/M/D H/M/S +utc
def get_time():
    naive_dt = datetime.now()
    aware_dt = naive_dt.astimezone()
    utc_dt = aware_dt.astimezone(timezone.utc)
    # date = utc_dt.isoformat(timespec='seconds')
    return utc_dt


# check why IP got listed, write the reason to reason.csv
def get_reason(ip, content):
    _impact = ""
    soup = BeautifulSoup(content, 'html.parser')
    table_tag = soup.find_all("table", {"class": "db", "border": "1", "width": "100%"})[0]
    rows = str(table_tag.find_all("tr")).split("\n")

    if not os.path.exists(PATH_REASON + '%s'%str(date.today())):
        os.makedirs(PATH_REASON + '%s'%str(date.today()))
    reason_location = os.path.join(PATH_REASON + '%s'%str(date.today()), FILE_Reason)
    if not os.path.exists(reason_location):
        with open(reason_location, 'w') as _wf:
            _wf.write('IP' + ',' + 'Impact' + ',' + 'Concrete_Allegation' + ',' + 'Time')
            _wf.write("\n")

    # get impact
    for _item in rows:
        _tmp_impact = BeautifulSoup(_item, 'html.parser').find_all("td")
        for _cell in _tmp_impact:
            if str(_cell).find("LISTED") > 0:
                _index_impact = (_tmp_impact.index(_cell)) + 1
                _impact = str(_tmp_impact[_index_impact]).split("<center>")[1][0]
                break
        break
    
    # get reason
    if  'THIS IS A PERMANENT LISTING' in content:
        _permanent = True
        _reason = 'No reason given'
    else:
        _permanent = False
        if 'Portscans' in content:
            _reason = 'Portscans or hacking attempts'
        elif 'spamtraps' in content:
            _reason = 'Tried to deliver mail to spamtraps'
        elif 'invalid credit cards' in content:
            _reason = "Invalid credit cards"
        else:
            _reason = "Other reason"
    delete_n_first_lines(FILE_Listed_IP,1)
    html_to_img(content,ip)
    write_to_csv(reason_location, (ip + ',' + _impact + ',' + _reason + ',' + get_time().isoformat(timespec='seconds')))
    # with open(reason_location, 'a') as f:
    #     # f.write('%s,'%ip+ '%s,'%_permanent + _reason + ',' + get_time().isoformat(timespec='seconds'))
    #     f.write(ip + ',' + _impact + ',' + _reason + ',' + get_time().isoformat(timespec='seconds'))
    #     f.write("\n")

# write to csv
def write_to_csv(_csvDir, _data):
    with open(_csvDir, 'a') as f:
        # f.write('%s,'%ip+ '%s,'%_permanent + _reason + ',' + get_time().isoformat(timespec='seconds'))
        f.write(_data)
        f.write("\n")

# if an ip is listed, take evidence and write to a .jpg file
def take_proof(ip):
    # 11 characters after 'subchannel value="'
    _wanted = 11
    _header = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0'}
    r = requests.get(UCE_Check_Link)
    
    _content1 = str(r.content)
    _subchannel= ((_content1).partition('subchannel value="')[2])[:_wanted]

    _post_data = {'whattocheck': 'IP', 'ipr': ip, 'subchannel': _subchannel}
    _final = requests.post(UCE_Check_Link, headers=_header, data=_post_data)
    _final = '%s'%_final.content
    _final = _final.replace('b\'' , '').replace('\\r' , '\r').replace('\\n' , '\n').replace('\'', '').replace('\\t', '\t')
    
    return _final


# delete n first line of a file
def delete_n_first_lines(filename,n):
    _lines = []
    with open(filename, 'r') as fp:
        _lines = fp.readlines()
    with open(filename, 'w') as fp:
        for _number, _line in enumerate(_lines):
            if _number not in range(0,n):
                fp.write(_line)


# preparation before starting connecting VPN
def preparation():
    subprocess.call([r'stop.bat'])
    _date_and_time = get_time()
    check_ip()
    call_api(FILE_VPN_List, VPNGate_Link)
    return _date_and_time


# Main function
def main():
    while True:
        try:
            date_and_time = preparation()

            # the first profile is in 3rd row
            counter = 4
            while True:
                if (counter < 3):
                    print("End of list, waiting for next turn")
                    print("Pushed to database")
                    time.sleep(INTERVAL)
                    date_and_time = preparation()
                    counter = 3
                    
                elif (counter == 90):
                    counter = 3
                    
                else:
                    print(counter - 2)
                    #create .ovpn file
                    create_VPN(counter)

                    #set config file (see in set-config.bat)
                    subprocess.call([r'set-config.bat'])
                
                    # start connection
                    subprocess.call([r'start.bat'])
                    time.sleep(20)
                
                    a = os.popen('curl -s ' + str(Public_IP_Check_Link)).readline()
                        
                    # for each VPN connection, take proof the first line ip then delete it, repeat 5 times
                    with open(FILE_Listed_IP, 'r+') as f1:
                        for i in range(0,5):
                            try:
                                firstline = f1.readline().rstrip()
                                # if no IP, break the for loop
                                if len(firstline) < 5:
                                    subprocess.call([r'stop.bat'])
                                    delete_n_first_lines(FILE_Listed_IP,1)
                                    counter = 1
                                    break
                                # take proof the IP in the first line then delete the first line
                                else:
                                    content = take_proof('%s'%firstline)
                                    # if content return spam warning, try other VPN connection
                                    if ('seems you are abusing' in content) or ('Connection aborted' in content) or ('was a problem with' in content):
                                        print("___Spam Warning, retry with other VPN___")
                                        break
                                    # if UCE's database is being updated, wait for few minutes and try other VPN connection
                                    elif ('Database is updating' in content) or ('click reload' in content):
                                        print("Please be patient, UCE's database is being updated")
                                        time.sleep(120)
                                        break
                                    # if everything is good, get evidence of the IP in firstline
                                    else:
                                        get_reason('%s'%firstline, content)
                                    i += 1
                                    print (str(i) + " - Checked - " + firstline)
                            except Exception as e:
                                print (e)
                                break

                # close current VPN connection (see in stop.bat)
                subprocess.call([r'stop.bat'])
                print ("\n------------------------------!!!NEXT!!!-----------------------------------\n")
                time.sleep(2)
                counter += 1
        except ConnectionError as e:
            print (e)
            continue
        
if __name__ == "__main__":
    main()