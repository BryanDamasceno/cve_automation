from selenium import webdriver
from selenium.webdriver.common.keys import Keys
import time
import requests

PATH = "/bin/chromedriver"
driver = webdriver.Chrome(PATH)


driver.get("https://www.cvedetails.com/vulnerability-search.php")

print(driver.title)

search = driver.find_element_by_id("vendor")
search.send_keys("zoom")
search.send_keys(Keys.RETURN)

driver.save_screenshot("CVEscreenshot.png")





url = 'https://www.virustotal.com/vtapi/v2/file/scan'
params = {'apikey': '43873059cdbb5bbfa716d3614e1b9ff4fae608415b85d0f5994430e3ddbab38e', 'resource': './screenshot.png'}
files = {'file': ('./screenshot.png', open('screenshot.png', 'rb'))}

response = requests.post(url, files=files, params=params)




scan = response.json()

url = 'https://www.virustotal.com/vtapi/v2/file/report'

params = {'apikey': '43873059cdbb5bbfa716d3614e1b9ff4fae608415b85d0f5994430e3ddbab38e', 'resource': scan["scan_id"]}

response = requests.get(url, params=params)

result = response.json()

print(result["verbose_msg"])
print("Positivos: ",result["scan_date"])
print(result["positives"])

driver.save_screenshot("VirusTotalscreenshot.png")



