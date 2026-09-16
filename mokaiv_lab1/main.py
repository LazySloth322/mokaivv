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
    for i in range(len(fileNames)):
        fileNames[i]=dirPath+fileNames[i]
    print(fileNames)

    return fileNames

def getInfo(fileName, mode=0): #0=base; 1=check
    with open(fileName, "r", encoding="utf-8") as file:
        data = json.load(file)

        if mode:
            reference = ["id","datetime","sender","subject","attachment","text"]
            dataKeys = list(data.keys())
            #print(dataKeys)
            try:
                for i in range(len(reference)):
                    if(dataKeys[i]!=reference[i]): return 1
            except Exception as e:
                print(e)
                return 1
            return 0
        elif not mode:
            pass

def validateEmail(fileNames):
    validList = []
    for file in fileNames:
        fileExtension=file.split(".")
        if fileExtension[len(fileExtension)-1]=="json":
            if getInfo(file,mode=1):
                print(file+" is invalid")
            else:
                validList.append(file)
    #print(validList)
    return validList


def main(dirPath):
    fileNames = getFileNames(dirPath)
    validMailList = validateEmail(fileNames)

    print(validMailList)


if __name__ == "__main__":
    dirPath = "./test/"
    main(dirPath)