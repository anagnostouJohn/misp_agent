import yara
import re
import fileinput
def check_yara(path):
    try:
        x = yara.compile(path)
        print("OK", x)
        return
    except yara.SyntaxError as err:
        f = err.args[0]
        #n = re.search(r'\((.*?)\)',f).group(1)#Eyresh kati pou einai anamesa se ()
        z = re.findall(r'"([^"]*)"', f) #Eyresh kati pou einai anamesa se ""
        print(type(z[0]))
        counter = 0
        with fileinput.FileInput(path, inplace=True) as file:
            for line in file:
                print(line.replace(z[0], (z[0]+str(counter))), end='')                
                counter+=1
        check_yara(path)

path = "yara_test.yara"
x = check_yara(path)
