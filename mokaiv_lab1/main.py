# TODO
# 1. check if email is valid (contain all necessary fields)
# 2. check spf (not working)
# 3. mark as phishing (suspicion coef: 0-valid, 0<...<2-sus, >2 phishing)
#   3.1 no link in mail +=0
#   3.2 https link +=1
#   3.3 http link +=2
#   3.4 sender domain doesnt equal link in mail +=1
#   3.5 key words? (ограничен, блокировке/заблокирован, заморожен, восстановить, отменен, ответить) +=1
#   3.6 there is an attachment +=1
# 4. return amount of phishing emails

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
            data = json.load(file)
            return [data["sender"],data["text"], data["attachment"]]


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

def verifyEmail(validMailList):
    result={"clean":[],"sus":[],"phishing":[]}
    susWords = ["ограничен","блокиров","заморожен","восстановит","отменен","ответить","ответьте"]
    for mail in validMailList:
        score = 0
        info = getInfo(mail)

        containsURL = False

        if ("http" in info[1]):
            containsURL=True
            if ("https" in info[1]):
                score+=1
            else:
                score+=2

        if containsURL:
            senderURL = info[0].split("@")[1]
            if not (senderURL in info[1]):
                score+=1

        for word in susWords:
            if (word in info[1]):
                score+=1
                break

        if info[2]:
            score+=1

        if score==0:
            result["clean"].append(mail)
        elif (score>0 and score<2):
            result["sus"].append(mail)
        elif (score>2):
            result["phishing"].append(mail)
    return result

def main(dirPath):
    fileNames = getFileNames(dirPath)
    totalAmount = len(fileNames)

    validMailList = validateEmail(fileNames)
    validAmount = len(validMailList)

    result = verifyEmail(validMailList)

    print("Valid emails: ", validAmount, " (total ",totalAmount,")")
    print("Clean emails: ",len(result["clean"]))
    print("Suspicious emails:",len(result["sus"]))
    print("Phishing emails: ",len(result["phishing"]))

    # print(result["clean"])
    # print(result["sus"])
    # print(result["phishing"])


if __name__ == "__main__":
    dirPath = "./test/"
    main(dirPath)