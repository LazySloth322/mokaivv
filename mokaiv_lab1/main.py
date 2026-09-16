# TODO
# 1. check if email is valid (contain all necessary fields)
# 2. check spf
# 3. check dkim
# 4. mark as phishing (dmarc)
# 5. return amount of phishing emails

import os
import json

def getFileNames(dirPath):
    fileNames = os.listdir(dirPath)
    print(fileNames)

    return fileNames

def validateEmail(fileNames):
    for file in fileNames:
        fileExtension=file.split(".")
        if fileExtension[len(fileExtension)-1]=="json":
            print(file)


        else:
            pass



def main(dirPath):
    fileNames = getFileNames(dirPath)
    validateEmail(fileNames)

    pass


if __name__ == "__main__":
    dirPath = "./test/"
    main(dirPath)