# -*- coding: utf-8 -*-
"""
Created on Sun Sep 17 21:21:59 2017

@author: elisaveta
"""

import json

class Json_Parser:
    
    
    file
    
    def __init__(self, path):
        with open(path, 'r') as json_data :
            self.file = json.load(json_data)
            
    def ppMaliciousActivity(self):
        for c in self.file['malicious_activity']:
            print("\n")
            print(c)
            


analyze = Json_Parser('//home//elisaveta//Dokumente//data.json')
analyze.ppMaliciousActivity()