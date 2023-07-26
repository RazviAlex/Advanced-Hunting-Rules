from grapi.grapi import Grapi
import json
import numpy as np
import os.path
from datetime import datetime, timedelta
import os
import logging

###**************************************###
#Rule: Detect when a user agent have 3 or more version in the same day (<24h).
#Idea:
#When malware makes external calls through some http/https protocol, it will usually check the browser installed on the computer to use a user agent with a similar version. 
#The hunting idea is when a user update the browser, during that day, if the user agent versions are collected, 2 different versions will be obtained.
#However, if the malware does not change the ua version, during that they you will obtain 3 different version with the same ua. 
#Example: malware is using ua version: "Mozilla/5.0 ... Chrome/115.0.0.0" and the user update UA from, "Mozilla/5.0 ... Chrome/115.1.0.0" to "Mozilla/5.0 ... Chrome/115.2.0.0" obtaining in that case 3 different version of the same UA in less than 24h.
###**************************************###

#log error message
logging.basicConfig(filename='error_log.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

#add ua and device to the dic
def add_values(key_device, splitUA, values_ua, fileName):
  listDict = []
  listUAalert = []
  contSameUA = 0
  fileName = "ua_anomaly_"+fileName
  listSplitUA = splitUA.split("/")
  for v in global_dict[key_device]:
    if listSplitUA[0] in v: #If it's true seems a previous UA was saved with a different version. It check if the UA from json is the same as the ua saved previous. The difference in that case is that it compare only the name without the version
      contSameUA = contSameUA + 1
      listUAalert.append(v)
      if contSameUA > 1: #just alert for thoese that match more than two previous UA existing
        with open(os.path.join('/opt/adv_ua_anomaly/anomalies',fileName), 'a') as file_alert:
          file_alert.write("[**]Alert. Devicehostaname ["+key_device+"] use same UA with different version. UA: ["+splitUA+"] ")
          for item in listUAalert:
            file_alert.write("[%s] " % item)
          file_alert.write("\n")
  listDict.append(splitUA)
  global_dict[key_device].extend(listDict)

#transform the UA: check if is a [Firefox, Edg, Chrome or Version(Safari)].
def transform_data(key_device, values_ua, fileName):
  mylist = []
  splitValues_ua = values_ua[-35:] #decrease the value len to optimize the loop
  if key_device not in global_dict:
    global_dict[key_device] = list()
  for splitUA in splitValues_ua.split(' '): #iterate all the values from the UA
    splitUA = splitUA[:-3]
    if 'Firefox' in splitUA and not any(splitUA in val for val in global_dict[key_device]): #check if the UA is Firefox & check if that UA/version was previous saved in the key
      add_values(key_device, splitUA, values_ua, fileName)
      break
    elif 'Edg' in splitUA and not any(splitUA in val for val in global_dict[key_device]):
      add_values(key_device, splitUA, values_ua, fileName)
      break
    elif 'Chrome' in splitUA and not any(splitUA in val for val in global_dict[key_device]):
      add_values(key_device, splitUA, values_ua, fileName)
      break
    elif 'Version' in splitUA and not any(splitUA in val for val in global_dict[key_device]):
      add_values(key_device, splitUA, values_ua, fileName)
      break


if __name__== "__main__":
  global_dict = {}
  #make a loop to solve the problem that elasticsearch only return 10k events.
  for timeRange in range(2, -1, -1):

    #config parameters
    lastD = datetime.today() - timedelta(hours=timeRange)
    logging.info('***************************************************************')
    logging.info('[**] Telemetry from: ' + lastD)
    logging.info('***************************************************************')

    for minuteRange in range(0, 60, 2):
      prevMin = lastD + timedelta(minutes=minuteRange)
      nextMin = lastD + timedelta(minutes=minuteRange) + timedelta(minutes=2)

      prevMin = prevMin.strftime("%Y-%m-%d %H:%M:%S")
      nextMin = nextMin.strftime("%Y-%m-%d %H:%M:%S")

      token = ""
      url = "http://127.0.0.1:9000/api/search/universal/absolute"
      my_api = Grapi(url, token)
      my_params = {#removing some UA from the query like Edge/19 and Edge/18 as they give lots of false positive (windows services use them) or urls that returns
        "query": "_exists_:eurl AND  _exists_:devicehostname AND _exists_:ua AND ua:*Mozilla* AND !ua:*AcrobatServices* AND !ua:*Edge\/18* AND !ua:*Edge\/19*", # Required
        "fields": "eurl", # Required
        #"range":3600,
        "from": prevMin, #"2022-03-22 20:00:00", # Required
        "to": nextMin, #"2022-03-21 8:51:00", # Required
        "limit": 10000 # Optional: Default limit is 150 in Graylog
      }

      #read data from the api
      response = my_api.send("get", **my_params)

      #convert data to json
      json_object = json.dumps(response.json())
      json_obj = json.loads(json_object)

      if "messages" in json_obj:
        lastD2 = datetime.today() - timedelta(hours=24)
        fileName = lastD2.strftime("%Y_%m_%d")
        for i in json_obj['messages']:
          #Example: Device-Name[**]Mozilla/5.0 (Windows..) (KHTML, like Gecko) Chrome/99.0.4844.74 Safari/537.36
          transform_data(i['message']['devicehostname'], i['message']['ua'], fileName)
      else:
        logging.error("[!] Error with json recieaved from graylog.")
