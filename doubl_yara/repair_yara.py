import yara
import re
import fileinput
import logging


def check_wrong_yara(path):
    book = open(path, "r")
    all_lines = book.read()
    f = all_lines.split("rule")
    #print(type(f))
    for i in f:
        print(type(i))
        try:
            yara.compile(source = "rule "+i)
        except Exception as err:  
            logging.error('Error in Yara File : ' + str(err) + " Yara File : " + i + "\n")
            f.remove(i)
    book.close()    
    file = open("clean.yara", "w")    
    for i in f:
        file.write("rule "+i+" \n")
    file.close()
    
def check_double_yara(path):
    try:
        yara.compile(path)
        return 
    except yara.SyntaxError as err:
        f = err.args[0]
        #n = re.search(r'\((.*?)\)',f).group(1)#Eyresh kati pou einai anamesa se ()
        z = re.findall(r'"([^"]*)"', f) #Eyresh kati pou einai anamesa se ""
        counter = 0
        with fileinput.FileInput(path, inplace=True) as file:
            for line in file:
                print(line.replace(z[0], (z[0]+str(counter))), end='')                
                counter+=1
    check_double_yara(path)
    
logging.basicConfig(format='%(asctime)s %(levelname)s %(message)s %(message)s',datefmt='%a, %d %b %Y %H:%M:%S',filename='program.log',level=logging.DEBUG)
path = "first.yara"
check_wrong_yara(path)
path = "clean.yara"
check_double_yara(path)
print("END")
