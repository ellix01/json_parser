# -*- coding: utf-8 -*-
"""
Created on Sun Sep 17 21:21:59 2017
@author: elisaveta
"""

import json
import os


class Analyzer:
    
    malware_samples = []
    
    def __init__(self, directory):
        self.dirpath = directory
        self.dir = os.listdir(directory)
        for file in self.dir:
            filepath = self.dirpath + "/" + file
            self.malware_samples.append(Sample(filepath))
            
    def sortFiles(self):
        for sample in self.malware_samples:
            if sample.isMalware() != True:
                print(sample.path)
                
        
            
            
                        

class Sample:
    
    
    def __init__(self, path):
        self.path = path
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
            
    def isMalware(self):
        score = self.file['score']
        if score < 40:
            return False
        else:
            return True 
        
    
        
        
    

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
        default = 'null'
        self.registry_reads = subject.get('registry_reads', default)
        self.file_reads = subject.get('file_reads', default)
        self.loaded_libraries = subject.get('loaded_libraries', default)
        self.process = subject.get('process', default)
        self.process_interactions = subject.get('process_interactions', default)
        self.memory_region_stages = subject.get('memory_region_stages', default)
        self.file_queries = subject.get('file_queries', default)
        self.registry_reads = subject.get('registry_reads', default)
        self.registry_reads = subject.get('registry_reads', default)

        self.id = x
        
        
        
    def readRegistries(self):
        for c in self.registry_reads:
            default = 'null'
            value = c.get('value', default)
            key = c.get('key', default)
            data = c.get('data', default)
            print("value: " + value)
            print("key: " + key)
            print("data: " + data)
            print("\n")
            
        
        
        
    
        

analyzer = Analyzer('C:/Users/esy2053/Documents/Lastline_report')
analyzer.sortFiles()





































