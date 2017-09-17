
import json

analysis = open('//home//elisaveta//Downloads//108fe917c9ff00100f33e9d902807b68.json', 'r')

file = json.load(analysis)
print(file['submission'])
