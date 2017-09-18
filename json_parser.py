# -*- coding: utf-8 -*-
"""
Created on Sun Sep 17 21:21:59 2017

@author: elisaveta
"""

import json

class Json_Parser:
    
    
    def __init__(self, path):
        with open(path, 'r') as json_data :
            self.file = json.load(json_data)
            self.report = Report(self.file['report'])
            self.reports = self.file['reports']
            self.malicious_activity = self.file['malicious_activity']
            self.analysis_subject = self.file['analysis_subject']
            
    def ppMaliciousActivity(self):
        for c in self.malicious_activity:
            print("\n")
            print(c)
            
    def getReport(self):
        for c in self.file['report']:
            print("\n")
            print(c)
    
    def getSubjectsCount(self):
        count = len(self.file['report']['analysis_subjects'])
        print(str(count))
        
    def getID(self):
        for i in range(0,5):
            id = self.file['report']['analysis_subjects'][i]['overview']['id']
            print(id)
    

class Report:
    
    analysis_subjects = []
    
    def __init__(self, report):
        self.report = report
        self.overview = report['overview']
        
        x = 0
        for anal in report['analysis_subjects']:
            self.analysis_subjects.append(Subject(report['analysis_subjects'][x], x))
            x += 1
        
    def subjectsSize(self):
        size = len(self.analysis_subjects)
        print(str(size))
        

class Subject: 
    
    def __init__(self, subject, x):
        self.subject = subject
        self.registry_reads = subject['registry_reads']
        self.id = x
        
        
        
    def readRegistries(self):
        for c in self.registry_reads:
            print(c)
            print("\n")
        
        
        
        
        
        
        
        

analyze = Json_Parser('//home//elisaveta//Dokumente//cryptowall.json')
analyze.report.analysis_subjects[1].readRegistries()
