#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu Sep  6 13:34:29 2018

@author: john
"""
import magic
import socket
import argparse
import zipfile
import yara
import json
import io
import sys
from pymisp import PyMISP
import hashlib
import time
import datetime
import re
from multiprocessing import Process
import winreg
import os
import psutil
import logging
import win32evtlog # requires pywin32 pre-installed
import urllib3
import signal
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
val = False

hKeys = []
hKeys_run = []
hKeys.append(winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Software\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Compatibility Assistant\\Store"))#AYTO
hKeys.append(winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache"))
hKeys.append(winreg.OpenKey(winreg.HKEY_USERS, "S-1-5-21-733142866-2450513131-3585932315-1001_Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache"))
hKeys.append(winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, "Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache"))


hKeys_run.append(winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion\\Run"))
hKeys_run.append(winreg.OpenKey(winreg.HKEY_CURRENT_USER,  "Software\\Microsoft\\Windows\\CurrentVersion\\Run"))
hKeys_run.append(winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,  "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"))
hKeys_run.append(winreg.OpenKey(winreg.HKEY_CURRENT_USER,  "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"))

paths = []
no_path = []




def reset_all():
    with open("paths.json", "w") as path_file:
        json.dump({"paths": [], "not_exist_paths": []}, path_file)
        path_file.close()
    with open("pids.json", "w") as pid_file:
        json.dump({"pids": []}, pid_file)
        pid_file.close()


def setup_logger(logger_name, log_file, level=logging.INFO):
    l = logging.getLogger(logger_name)
    formatter = logging.Formatter('%(asctime)s : %(message)s')
    fileHandler = logging.FileHandler(log_file, mode='a')
    fileHandler.setFormatter(formatter)
    l.setLevel(level)
    l.addHandler(fileHandler)


def get_stats_zip(path, matches):
    name = str(matches[0])+"_"+os.path.basename(path)
    my_zip = zipfile.ZipFile(os.getcwd()+r"\bad_files\_"+name+".zip","w",zipfile.ZIP_DEFLATED)
    md5 = hashlib.md5()
    sha = hashlib.sha256()
    f = open(path,"rb").read()
    md5.update(f)
    sha.update(f)
    infos = open("info.txt","w")
    infos.write(f"Path : {path} \n \n")
    infos.write(f"Name of file : {os.path.expandvars(path)} \n")
    infos.write(f"INFO : {magic.from_file(path)}\n")
    infos.write(f"Creation Time : {datetime.datetime.fromtimestamp(os.path.getctime(path)).strftime('%c')} \n")
    infos.write(f"Last Access : {datetime.datetime.fromtimestamp(os.path.getatime(path)).strftime('%c')} \n")
    infos.write(f"Last Modification : {datetime.datetime.fromtimestamp(os.path.getmtime(path)).strftime('%c')} \n")
    infos.write(f"Size in bytes : {os.path.getsize(path)} \n")
    infos.write(f"Protection Bits : {os.stat(path).st_mode} \n")
    infos.write(f"Inode Number : {os.stat(path).st_ino} \n")
    infos.write(f"Device : {os.stat(path).st_dev} \n")
    infos.write(f"Number of Hard Links : {os.stat(path).st_nlink} \n")
    infos.write(f"User id of Owner : {os.stat(path).st_uid} \n")
    infos.write(f"Group id of Owner : {os.stat(path).st_gid} \n")
    infos.write(f"MD5 : {md5.hexdigest()} \n")
    infos.write(f"SHA 256 : {sha.hexdigest()} \n")
    infos.write(f"YARA MATCHES: {matches} \n")
    infos.close()
    time.sleep(0.1)
    my_zip.write("info.txt")
    my_zip.write(path)
    my_zip.close()
    time.sleep(0.1)
    os.remove(path)
    os.remove("info.txt")

def inser_to_paths(path):
    global paths
    if path not in paths:
        paths.append(path)
    else:
        pass

def get_ps():
    server = 'localhost' # name of the target computer to get event logs
    logtype = 'Windows PowerShell' # 'Application' # 'Security' # 'Windows PowerShell'
    hand = win32evtlog.OpenEventLog(server,logtype)
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ|win32evtlog.EVENTLOG_SEQUENTIAL_READ
    total = win32evtlog.GetNumberOfEventLogRecords(hand)
    while True:
        events = win32evtlog.ReadEventLog(hand, flags,0)
        if events:
            for event in events:
                data = event.StringInserts
                if data:
                    for msg in data:
                        msg = msg.split("\n")
                        for i in msg :
                            if "HostApplication" in i:
                                path = i.split()[-1][1:len(i.split()[-1])-1]
                                if os.path.isabs(path):
                                    inser_to_paths(path)
        else:
            break


def get_paths(decission, list):
    global  paths
    global no_path
    for hKey in list:
       # print("---------------------------------------------------------------------------------------------------------------------------")
        try:
            count = 0
            while 1:
                name, value, Enum_type = winreg.EnumValue(hKey, count)
                if decission == "RUN":
                    path = value.lower().split(".exe")[0] + ".exe"
                    path = path[1:]
                elif decission == "NO_RUN":
                    path = name.lower().split(".exe")[0]+".exe"
                count = count + 1
                if path.startswith("\\"):
                    #print(type(path))
                    path = path.replace("\\","/")
                    file_log.warning('A programm has been executed from server location') ##################################################<<<<<<<<<<<<<<<<<<<<<<<<<
                elif os.path.isabs(path):
                    inser_to_paths(path)
                else:
                    print("No such path", path)
        except WindowsError as err7:
            file_log.warning(f'Windows error {err7}')
            pass


def check_yara():
    file_path = os.getcwd()+'/iocs/yara'
    errors=0
    count=0
    filepaths_ok = dict()
    for root, dirs, files in os.walk(file_path):
        for name in files:
            path = os.path.join(root, name)
            try:
                x = yara.compile(path)
                filepaths_ok[name] = path
            except yara.Error as err:
                main_sys_log.error(f"Wrong Yara File : {name}, errors {err}")
                errors += 1
                continue
    rule = yara.compile(filepaths=filepaths_ok)
    rule.save("saved_yara_file.yara")
    del rule
    # with open("pids.json", "w") as pids_j:
    #     jsonx={"pids": [{"id": "", "name": "", "create_time": ""}]}
    #     json.dump(jsonx, pids_j)
    #     pids_j.close()
    with open("paths.json", "w") as paths_json:
        jsony = {"paths": [], "not_exist_paths": []}
        json.dump(jsony, paths_json)
        paths_json.close()


def find_procs_by_name():
    "Return a list of processes matching 'name'."
    global paths
    for p in psutil.process_iter():
        try:

            if p.name() == "cmd.exe":
                #print(p.cmdline())
                for i in p.cmdline():
                    if os.path.isabs(i):
                        inser_to_paths(i)
                    else:
                        continue

            elif p.name() == "python.exe":
                for i in p.cmdline():
                    if os.path.isabs(i):
                        inser_to_paths(i)
                    else:
                        continue
            else:
                try:
                    inser_to_paths(p.exe())
                    x = p.parent().exe()
                    inser_to_paths(x)
                except AttributeError as err:
                    file_log.warning(f"Processes : {err} for {p}")
                    pass
                    #print("Attribute Error", err)
        except (psutil.AccessDenied, psutil.ZombieProcess) as err2:
            file_log.warning(f'Access Denied {err2} for {p}')

            pass
        except psutil.NoSuchProcess as err3:
            file_log.warning(f'No such Process {err3} for {p}')
            continue


def collect():
    with open('paths.json', "r") as p:
        json_paths = json.load(p)
        p.close()
    get_ps()
    first = ("RUN", hKeys_run)
    second = ("NO_RUN", hKeys)
    get_paths(first[0],first[1])
    get_paths(second[0],second[1])
    find_procs_by_name()
    counter = 0
    compiled_yara = yara.load("saved_yara_file.yara")
    for path in paths:
        try:
            with open(path, "rb", buffering=2000000) as f:
                    print(path)
                    matches = compiled_yara.match(data=f.read())
                    f.close()
                    if matches:
                        print("ITS A MATCHHHHH",path)

                        base_name = os.path.basename(path)
                        for p in psutil.process_iter():
                            if base_name == p.name():
                                p.kill()
                        get_stats_zip(path, matches)
        except Exception as err:
            print(err)
            continue

def yaramem():
    with open("pids.json", "r") as js_f:
        from_file_pids = json.load(js_f)
        js_f.close()
    try:
        while True:
            compiled_yara = yara.load("saved_yara_file.yara")
            # with open("pids.json", "r") as js_f:
            #     from_file_pids = json.load(js_f)
            #     js_f.close()
            counter = 0
            failed = 0
            mypid = os.getpid()
            myppid = os.getppid()

            for myProcess in psutil.process_iter():
                try:
                    pinfo = myProcess.as_dict(attrs=['pid', 'name', 'exe', 'cmdline', 'create_time','ppid'])
                    counter = counter + 1
                    if pinfo['pid'] == mypid:
                        continue
                    elif pinfo['ppid']==myppid:
                        continue
                    elif pinfo['pid'] == myppid:
                        continue
                    elif pinfo["name"] == "pycharm64.exe":
                        continue
                    elif pinfo["name"] == "vmware.exe":
                        continue


                    else:
                        check = (pinfo["pid"],pinfo["create_time"])
                        if check not in from_file_pids["pids"]:

                            from_file_pids["pids"].append(check)
                            match = compiled_yara.match(pid = pinfo["pid"])
                            if match:
                                print(pinfo['name'], "--------------",pinfo["pid"], "--------------",match)
                                p_to_kill = psutil.Process(pinfo["pid"])
                                os.kill(p_to_kill.parent().pid, signal.SIGTERM)
                                os.kill(p_to_kill.pid,signal.SIGTERM)
                                #os.kill(pinfo["pid"])
                                memory_log.warning(f"Found malicious application name : {pinfo['name']} path : {pinfo['exe']} PID {pinfo['pid']}  ")
                                get_stats_zip(pinfo['exe'], match)
                        else:
                            print("passing")
                except Exception as err:
                    memory_log.warning(f"Exception while scanning Process {err}  ")
            print("END")
            time.sleep(0.9)
    except yara.Error as err:
        print("ERROR", err)


def stop_conns():
    while True:
        file = open(os.getcwd()+r"\iocs\misp-c2-iocs.txt", "r")
        l_file = file.readlines()
        file.close()
        ips= list()
        for i in l_file:
            ips.append(i.split(",")[0])
        #print(ips)
        x = psutil.net_connections(kind="all")
        for i in x:
            try:
                if i.raddr.ip in ips:
                    p = psutil.Process(i.pid)
                    print(f"IP: {i.raddr.ip}, Port: {i.raddr.port}, Executable: {p.name()}, pid: {i.pid}, Started: {datetime.datetime.fromtimestamp(p.create_time()).strftime('%c')}")
                    connect_log.warning(f"IP: {i.raddr.ip}, Port: {i.raddr.port}, Executable: {p.name()}, pid: {i.pid}, Started: {datetime.datetime.fromtimestamp(p.create_time()).strftime('%c')}")

                    os.kill(p.parent().pid , signal.SIGTERM)
                    os.kill(i.pid, signal.SIGTERM)
            except:
                continue



class MISPReceiver(Process):
    hash_iocs = {}
    filename_iocs = {}
    c2_iocs = {}
    yara_rules = {}
    debugon = False
    # Output
    siem_mode = False
    separator = ";"
    use_headers = False
    use_filename_regex = True
    def __init__(self, data,path_to_yara,path_to_ioc, misp_key, misp_url, misp_verify_cert, siem_mode=False, debugon=False):
        super(MISPReceiver, self).__init__()
        self.debugon = debugon
        self.data = data
        try:

            self.misp = PyMISP(misp_url, misp_key, misp_verify_cert, 'json')
            print("HELLO")
        except Exception as err:
            main_sys_log.error(f"Connection Failed {err}")
            print("Cannot Connect to MISP : ", err)
            sys.exit()

        if siem_mode:
            self.output_path= path_to_ioc
            self.output_path_yara =path_to_yara
            self.siem_mode = True
            self.separator = ","
            self.use_headers = True
            self.use_filename_regex = False

    def run(self):
        while True:
            self.get_iocs_last()
            self.write_iocs(self.output_path, self.output_path_yara )
            check_yara()
            print("RUN")
            time.sleep(5)
            reset_all()

    def get_some_last(self,event_element):
                f_l=dict()
                f_l["id"] = event_element["Event"]["id"]
                f_l["attribs"]=[]
                self.data["Events"].append(f_l)
                event = event_element["Event"]
                # Info for Comment
                info = event['info']
                #print ("INFO-------------",info)
                uuid = event['uuid']
                comment = "{0} - UUID: {1}".format(info, uuid)
                # Event data
                for attribute in event['Attribute']:
                    self.data["Events"][-1]["attribs"].append(attribute["id"])
                    # Skip iocs that are not meant for ioc detection
                    if attribute['to_ids'] == False:
                        continue
                    # Value
                    value = attribute['value']
                    # Non split type
                    if '|' not in attribute['type']:
                        self.add_ioc(attribute['type'], value, comment, uuid, info)
                    # Split type
                    else:
                        # Prepare values
                        type1, type2 = attribute['type'].split('|')
                        value1, value2 = value.split('|')
                        # self.add_ioc(type1, value1, comment)
                        self.add_ioc(type2, value2, comment, uuid, info)

    def get_only_one_attrib(self,event_element,v):
        info = event_element['Event']['info']
        uuid = event_element['Event']['uuid']
        comment = "{0} - UUID: {1}".format(info, uuid)
        for e in event_element['Event']['Attribute']:
            #EXO TO EVENT POU DEN EXO TO NEO ATTRIBUTE EXO TO ID TIU ATTRIBUTE TOU EVENT
            if e["id"] in v:
                # Skip iocs that are not meant for ioc detection
                if e['to_ids'] == False:
                    return
                # Value
                for data_event in self.data["Events"]:
                    if data_event["id"]==event_element['Event']["id"]:
                        data_event["attribs"].append(e["id"])
                value = e['value']
                # Non split type
                if '|' not in e['type']:
                    self.add_ioc(e['type'], value, comment, uuid, info)
                # Split type
                else:
                    # Prepare values
                    type1, type2 = e['type'].split('|')
                    value1, value2 = value.split('|')
                    # self.add_ioc(type1, value1, comment)
                    self.add_ioc(type2, value2, comment, uuid, info)

    def get_iocs_last(self):

        result = self.misp.get_events_last_modified(self.data["search_from"])
        print(result)
        self.events = result['response']
        t1 = datetime.datetime.strptime(self.events[-1]["Event"]["date"], "%Y-%m-%d").date()
        self.data["search_from"]= str(t1 - datetime.timedelta(days=10))# take from the last event the date
        # Process each element (without related eevents)
        ids_of_json = [element['id'] for element in self.data['Events']]
        for event_element in self.events:
            if event_element["Event"]["id"] not in ids_of_json: # IF event is inside MISP but not in Json
                ######################################################
                self.get_some_last(event_element)
            elif event_element["Event"]["id"] in ids_of_json:# IF event is MISP and in Json, must tcheck if all attribs are inside Json
                spec_misp_attributes_ids = [attrib_id['id'] for attrib_id in event_element['Event']["Attribute"]] # Get all Attributes ids from specific event
                for i in self.data['Events']: #For all events
                    if i["id"]==event_element["Event"]["id"]: #Find specific event
                        no_attribs = list(set(spec_misp_attributes_ids)-set(i["attribs"])) #find deferences ffrom attributes
                        if len(no_attribs) != 0:
                            self.get_only_one_attrib(event_element,no_attribs)
            with open('keys.json', 'w') as outfile:
                json.dump(self.data, outfile)
                outfile.close()

    def add_ioc(self, ioc_type, value, comment, uuid, info):
        # Cleanup value
        value = value
        # Debug
        if self.debugon:
            print("{0} = {1}".format(ioc_type, value))
        # C2s
        if ioc_type in ('hostname', 'ip-dst', 'domain'):
            if value == '127.0.0.1':
                return
            self.c2_iocs[value] = comment
        # Hash
        if ioc_type in ('md5', 'sha1', 'sha256'):
            # No empty files
            if value == 'd41d8cd98f00b204e9800998ecf8427e' or \
                            value == 'da39a3ee5e6b4b0d3255bfef95601890afd80709' or \
                            value == 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855':
                return
            self.hash_iocs[value] = comment
        # Filenames
        if ioc_type in ('filename', 'filepath'):
            # Add prefix to filenames
            if not re.search(r'^([a-zA-Z]:|%)', value):
                if not self.siem_mode:
                    value = "\\\\{0}".format(value)
            if self.use_filename_regex:
                self.filename_iocs[my_escape(value)] = comment
            else:
                self.filename_iocs[value] = comment #<<<<<<<<<<<<<<<<<<<<<<<<
        # Yara
        if ioc_type in ('yara'):
            self.add_yara_rule(value, uuid, info)

    def add_yara_rule(self, yara_rule, uuid, info):
        identifier = generate_identifier(info)
        self.yara_rules[identifier] = r'%s' % repair_yara_rule(yara_rule, uuid)#<<<<<<<<<<<<<<<<<<<<<<<<

    def write_iocs(self, output_path, output_path_yara):
        # Write C2 IOCs
        self.write_file(os.path.join(output_path, "misp-c2-iocs.txt"), self.c2_iocs, "c2")
        self.c2_iocs.clear()
        # Write Filename IOCs
        self.write_file(os.path.join(output_path, "misp-filename-iocs.txt"), self.filename_iocs, "filename")
        self.filename_iocs.clear()
        # Write Hash IOCs
        self.write_file(os.path.join(output_path, "misp-hash-iocs.txt"), self.hash_iocs, "hash")
        self.hash_iocs.clear()
        # Yara
        if len(self.yara_rules) > 0:
            # Create dir if not exists
            if not os.path.exists(output_path_yara):
                os.makedirs(output_path_yara)
            # Loop through rules (keys are identifiers used for file names)
            for yara_rule in self.yara_rules:
                output_rule_filename = os.path.join(output_path_yara, "%s.yar" % yara_rule)
                self.write_yara_rule(output_rule_filename, self.yara_rules[yara_rule])
            #logging.info("{0} YARA rules written to directory {1}".format(len(self.yara_rules), output_path_yara))
            if len(self.yara_rules) == 0:
                print("NO NEW RULES") #<<<<<<<<<<<<<<<<<<<<<<<<<<<NA SVISEI
                pass
            else:
                num_of_rules = len(self.yara_rules)
                main_sys_log.info(f"{num_of_rules} YARA rules written to directory {output_path_yara}")
                print(f"{num_of_rules} YARA rules written to directory {output_path_yara}") #<<<<<<<<<<<<<<<<<<<<<<<<<<<NA SVISEI
            self.yara_rules.clear()

    def write_file(self, ioc_file, iocs, ioc_type):
        with open(ioc_file, 'a') as file:
            for ioc in iocs:
                file.write("{0}{2}{1}\n".format(ioc, iocs[ioc], self.separator))
        if len(iocs) != 0:
            main_sys_log.info(f"{len(iocs)} IOCs written to file {ioc_file}")

        print("{0} IOCs written to file {1}".format(len(iocs), ioc_file)) #<<<<<<<<<<<<<<<<<<<<<<<<<<<NA SVISEI

    def write_yara_rule(self, yara_file, yara_rule):
        # Write the YARA rule
        if not os.path.isfile(yara_file):
            with io.open(yara_file, 'w', newline="\n") as fh:
                yara_rule = yara_rule.replace("\\t","\t")
                yara_rule = yara_rule.replace("\\r", "\r")
                fh.write(yara_rule.replace("\\n", "\n"))
            #fh.write(yara_rule.replace("\\n", " /n " ))


def my_escape(string):
    # Escaping
    string = re.sub(r'([\-\(\)\.\[\]\{\}\\\+])',r'\\\1',string)
    # Fix the cases in which the value has already been escaped
    string = re.sub(r'\\\\\\\\',r'\\\\',string)
    return string


def get_data_json():
    path_to_json = os.getcwd()+"/keys.json"
    path_to_pids = os.getcwd() + "/pids.json"
    if not os.path.isfile(path_to_json):
        with open("keys.json","w") as file:
            json.dump({"id": "", "url": "", "cert": "False", "search_from": "2000-1-1", "Events": []}, file)
            main_sys_log.error("Valid Json File Has been Created Please provide proper information")
            print("Provide valid Json File") #<<<<<<<<<<<<<<<<<<<<<<<<<<<NA SVISEI
            sys.exit()
    if not os.path.isfile(path_to_pids):
        with open("pids.json", "w") as file:
            json.dump({"pids": []},file)
            file.close()

    else:
        with open('keys.json') as f:
            data = json.load(f)
            if data["cert"] == "True":
                val = True
            elif data["cert"] == "False":
                val = False
            else:
                main_sys_log.error("Please Verify the server certificate")
                print("Please Verify the server certificate") #<<<<<<<<<<<<<<<<<<<<<<<<<<<NA SVISEI
                sys.exit()
        if len(data["id"]) != 40:
            main_sys_log.critical("Set correct an API key")
            print("Set correct an API key") #<<<<<<<<<<<<<<<<<<<<<<<<<<<NA SVISEI
            sys.exit()
        else:
            return data


def generate_identifier(string):
    valid_chars = '-_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    return ''.join(char for char in string if char in valid_chars)

def repair_yara_rule(yara_rule, uuid):
    # Wrong upper ticks when copied & pasted from a PDF
    yara_rule = yara_rule.replace('\u201c', r'"')
    yara_rule = yara_rule.replace('\u201d', r'"')
    # Missing rule name
    name = uuid.replace('-', '_')
    # yara_rule = re.sub(r'^[\W]*\{', 'rule rule_%s {' % name, yara_rule.replace("\\n", " "))
    yara_rule = re.sub(r'^[\W]*\{', 'rule rule_%s {' % name, yara_rule)
    return yara_rule


def main(path_to_yara, path_to_ioc):
    count = 0
    try:
        data = get_data_json()
        misp_receiver = MISPReceiver(data, path_to_yara, path_to_ioc, misp_key=data["id"], misp_url=data["url"],misp_verify_cert=val, siem_mode=True, debugon=False)
        misp_receiver.start()
        time.sleep(5)
        p1 = Process(target=yaramem)
        p2 = Process(target=stop_conns)
        p1.start()
        p2.start()
        #misp_receiver.join()
        #p1.start()
        #p1.join()
        while True:

            if os.path.isfile("saved_yara_file.yara"):
                try:
                    print("WATE")
                    yara.load("saved_yara_file.yara")
                    collect()
                    time.sleep(0.4)
                except Exception as err:
                    print("problem with yara : ", err)
            else:
                print("No sutch file")
            print("SCANNING END")
    except:
        count += 1
        if count != 2:
            main(path_to_yara, path_to_ioc)
        else:
            main_sys_log.error("Total system fail")




setup_logger('main_sys', os.getcwd()+r'\main_sys.log')
setup_logger('file', os.getcwd()+r'\file.log')
setup_logger('memory', os.getcwd()+r'\memory.log')
setup_logger('connect', os.getcwd()+r'\connect.log')
main_sys_log = logging.getLogger('main_sys')
file_log = logging.getLogger('file')
memory_log = logging.getLogger('memory')
connect_log = logging.getLogger('connect')

if __name__ == '__main__':


    parser = argparse.ArgumentParser(description="Socket Server Example")
    parser.add_argument('-r','--reset',dest="reset", action="store_true", required=False)
    parser.add_argument('-k', '--key',dest="key", type=str, required=False)
    parser.add_argument('-u', '--url',dest="url", type=str, required=False)
    given_args = parser.parse_args()

    try:
        path_to_yara = os.getcwd() + '/iocs/yara'
        path_to_ioc = os.getcwd() + '/iocs'
        bad_files = os.getcwd() + '/bad_files'

        if not os.path.isfile("paths.json"):
            with open("paths.json", "w") as file:
                json.dump({"paths": [],"not_exist_paths":[]}, file)
        if not os.path.exists(path_to_ioc):
            os.makedirs(path_to_ioc)
        if not os.path.exists(path_to_yara):
            os.makedirs(path_to_yara)
        if not os.path.exists(bad_files):
            os.makedirs(bad_files)
        if given_args.reset:
            reset_all()
        if given_args.key:
            if len(given_args.key) != 40:
                main_sys_log.critical("Set correct an API key")
                sys.exit()
            else:
                with open("keys.json", "r") as js_f:
                    pids = json.load(js_f)
                    pids['id']=None
                    js_f.close()
                with open("keys.json", "w") as js_f:
                    pids['id'] = given_args.key
                    json.dump(pids, js_f)
                js_f.close()
        if given_args.url:
            try:
                socket.inet_aton(given_args.url)
                with open("keys.json", "r") as js_f:
                    pids = json.load(js_f)
                    pids['url']=None
                    js_f.close()
                with open("keys.json", "w") as js_f:
                    pids['url'] = given_args.url
                    json.dump(pids, js_f)
                    js_f.close()
            except socket.error as err:
                main_sys_log.error("No valid IP format")


        main(path_to_yara, path_to_ioc)
    except KeyboardInterrupt:
        print("closed")
