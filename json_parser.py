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
        size = len(report['analysis_subjects'])
        for i in range(1, size):
            print(str(i))
            self.analysis_subjects[i] = Subject(report['analysis_subjects'][i])
        
    def subjectsSize(self):
        size = len(self.analysis_subjects)
        print(str(size))
        

class Subject: 
    
    def __init__(self, subject):
        """self.registry_reads = subject['registry_reads']
        self.file_reads = subject['file_reads']
        self.loaded_libraries = subject['loaded_libraries']
        self.process = subject['process']
        self.process_interactions = subject['process_interactions']
        self.file_queries = subject['file_queries']
        self.strings_lists = subject['strings_lists']
        self.strings_lists = subject['strings_lists']
        self.overview = subject['overview']
        
        if 'raised_exceptions' in subject['raised_exceptions']:
            self.raised_exceptions = subject['raised_exceptions']
        self.frequent_api_calls = subject['frequent_api_calls']
        self.file_searches = subject['file_searches']
        
    def readRegistries(self):
        for c in self.registry_reads:
            print(c)
            print("\n")"""
        
        
        
        
        
        
        
        

analyze = Json_Parser('C:/Users/esy2053/Documents/Lastline_report/ransom.json')
analyze.report.subjectsSize()
