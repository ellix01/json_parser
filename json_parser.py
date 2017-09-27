# -*- coding: utf-8 -*-
"""
Created on Sun Sep 17 21:21:59 2017
@author: elisaveta
"""

import json
import re
import os


class Analyzer:
    
    
    def __init__(self, directory):
        self.malware_samples = []
        self.dirpath = directory
        self.dir = os.listdir(directory)
        for file in self.dir:
            filepath = self.dirpath + "/" + file
            self.malware_samples.append(Sample(filepath))
            
    def sortFiles(self):
        for sample in self.malware_samples:
            if sample.isMalware() != True:
                print(sample.path)
                
    def IndiaktorUsedRegisry(self, registry):
        for sample in self.malware_samples:
            x = sample.report.checkReportForRegistry(registry)
            if x:
                return True
            else:
                continue
        return False
        
    
            
    
    
            
                        

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
    
    
    def __init__(self, report):
        self.analysis_subjects = []
        self.report = report
        self.overview = report['overview']
        
        x = 0
        for anal in report['analysis_subjects']:
            self.analysis_subjects.append(Subject(report['analysis_subjects'][x], x))
            x += 1
        
    def subjectsSize(self):
        size = len(self.analysis_subjects)
        print(str(size))
        
    def checkReportForRegistry(self, registry):
        for subject in self.analysis_subjects:
            if subject.checkSubjectForRegistry(registry):
                return True
            else:
                continue
        return False
    
    def checkReportSusFileWrites(self):
        for subject in self.analysis_subjects:
            if subject.checkSubjectSusFileWrites():
                return True
            else:
                continue
        return False
    
            
        
        

class Subject: 
    
    def __init__(self, subject, x):
        self.subject = subject
        default = 'null'
        self.registry_reads = subject.get('registry_reads', default)
        self.file_reads = subject.get('file_reads', default)
        self.file_writes = subject.get('file_writes', default)
        self.loaded_libraries = subject.get('loaded_libraries', default)
        self.process = subject.get('process', default)
        self.process_interactions = subject.get('process_interactions', default)
        self.memory_region_stages = subject.get('memory_region_stages', default)
        self.file_queries = subject.get('file_queries', default)
        self.registry_writes = subject.get('registry_writes', default)
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
            
    def checkSubjectForRegistry(self, registry):
        if self.registry_writes == 'null':
            return False
        for c in self.registry_writes:
            default = 'null'
            key = c.get('key', default)
            if registry in key:
                return True
            else:
                continue 
        return False
    
    def checkSubjectSusFileWrites(self):
        if self.file_writes == 'null': 
            return False
        for c in self.file_writes:
            default = 'null'
            filename = c.get('filename', default)
            if suspiciousName(filename):
                print(filename)
                return True
            else:
                continue
        return False 
            
        
        
        
    
        

#analyzer = Analyzer('C:/Users/esy2053/Documents/Lastline_report')
#analyzer.IndiaktorUsedRegisry('CURRENTVERSION\RUN')

#sample = Sample('C:/Users/esy2053/Documents/Lastline_report/data (2).json')
#sample.report.checkReportForRegistry('CURRENTVERSION\RUN')
#[a-zA-Z].*\d+.*[a-zA-Z]\.exe


sample = Sample('C:/Users/esy2053/Documents/Lastline_report/data (2).json')
x = sample.report.checkReportSusFileWrites()
print(str(x))

def suspiciousName(name):
    if len(name) > 5:
        if re.search(r".*\\[a-zA-Z].*\d+[a-zA-Z]+.*", name):
            if '32' in name:
                return False
            return True
        else:
            return False


        
        
#s = 'C:\\Windows'
#x = suspiciousName(s)
#print(str(x))




































