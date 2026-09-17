# TODO
# 1. check if email is valid (contain all necessary fields)
# 2. check spf (not working)
# 3. check if email contain http web links and sus words
# 4. mark as phishing (maybe suspicion coef?)
# 5. return amount of phishing emails

import os
import json
import dns.resolver

def getFileNames(dirPath):
    fileNames = os.listdir(dirPath)
    for i in range(len(fileNames)):
        fileNames[i]=dirPath+fileNames[i]
    #print(fileNames)

    return fileNames

def getInfo(fileName, mode=0): #0=base; 1=check
    with open(fileName, "r", encoding="utf-8") as file:
        if mode:
            reference = ["id","datetime","sender","subject","attachment","text"]
            #print(dataKeys)
            try:
                data = json.load(file)
                dataKeys = list(data.keys())
                for i in range(len(reference)):
                    if(dataKeys[i]!=reference[i]): return 1
            except Exception as e:
                #print(e)
                return 1
            return 0
        elif not mode:

            #get sender link
            #get subject
            #get text

            data = json.load(file)
            print(data["subject"]+"\n"+data["text"])


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

def getSPF(domain):
    for rec in dns.resolver.resolve(domain, "TXT"):
        txt = b"".join(rec.strings).decode()
        if txt.startswith("v=spf1"):
            return txt
    return None


def main(dirPath):
    fileNames = getFileNames(dirPath)
    totalAmount = len(fileNames)

    validMailList = validateEmail(fileNames)
    validAmount = len(validMailList)

    print(validMailList)

    for mail in validMailList:
        getInfo(mail)
        #call for phishing check

    # for i in range(validAmount):
    #     with open(validMailList[i], "r", encoding="utf-8") as file:
    #         data = json.load(file)
    #         try:
    #             print(getSPF(data["sender"].split("@")[1]))
    #         except Exception as e:
    #             print(e)


if __name__ == "__main__":
    dirPath = "./test/"
    main(dirPath)