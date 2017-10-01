# -*- coding: utf-8 -*-
"""
Created on Sun Sep 17 21:21:59 2017
@author: elisaveta
"""

import json
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
        
    def Indikator1(self):
        for sample in self.malware_samples:
            print(sample.path)
            x = 0
            for subject in sample.report.analysis_subjects:
                x += subject.indikatorOne()
            if x > 30:
                sample.Indikator1 = True
            print(str(sample.Indikator1))
                
    def Indikator2(self):
        registry = ['WINLOGON', 'RUN', 'RUNONCE', 'MICROSOFT\WINDOWS\CURRENTVERSION\EXPLORER\ADVANCED']
        for sample in self.malware_samples:
            print(sample.path)
            for reg in registry:
                x = sample.report.checkReportForRegistry(reg)
                if x == True:
                    sample.Indikator2 = x
            print(str(sample.Indikator2))
            
            
    def Indikator3(self):
        for sample in self.malware_samples:
            print(sample.path)
            for subject in sample.report.analysis_subjects:
                x = subject.indikatorThree('vssadmin.exe Delete Shadows /All /Quiet')
                if x == True:
                    sample.Indikator3 = x
            print(str(sample.Indikator3))
            
    def Indikator4(self):
        for sample in self.malware_samples:
            print(sample.path)
            for subject in sample.report.analysis_subjects:
                x = subject.indikatorFour()
                if x == True:
                    sample.Indikator4 = x
            print(str(sample.Indikator4))
                
        
    def Inidkator5(self):
        x = ['xpsp2res.dll', 'cryptsp.dll', 'ntoskrnl.exe', 'jqs.exe']
        for sample in self.malware_samples:
            a = sample.IndikatorFive(x)
            print(sample.path)
            print(str(a))
            
    
        
                        

class Sample:
    def __init__(self, path):
        self.path = path
        self.Indikator1 = False
        self.Indikator2 = False
        self.Indikator3 = False
        self.Indikator4 = False

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
        
    def IndikatorFive(self, x):
        y = x
        for subject in self.report.analysis_subjects:
            a = subject.indikatorFive(y)
            if a == 'null':
                continue
            y.remove(a)
        if (len(x) - len(y)) > 3:
            return True 
        return False
    

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
    
    def indikatorOne(self):
        if self.file_writes == 'null':
            return -1 
        x = 0
        for write in self.file_writes:
            default = 'null'
            filename = write.get('filename', default)
            if not '.dll' in filename:
                x += 1
        return x        
        
    def indikatorThree(self, arg):
        if self.process_interactions == 'null':
            return False
        default = 'null'
        for interaction in self.process_interactions:
            argument = interaction.get('arguments', default)
            if arg in argument:
                return True
        return False
        
    def indikatorFour(self):
        if self.file_writes == 'null':
            return False
        for write in self.file_writes:
            default = 'null'
            pe_info = write.get('static_pe_information', default)
            if pe_info != 'null':
                time = pe_info.get('compile_timestamp', default)
                year = int(time[0:4])
                if year < 2000:
                    return True
            
            
    
    def indikatorFive(self, processes):
        if self.loaded_libraries == 'null' :
            return 'null'
        default = 'null'
        x = 0
        for lib in self.loaded_libraries:
            filename = lib.get('filename', default)
            if filename == 'null':
                continue
            for proc in processes:
                if proc in filename:
                    print(proc)
                    return proc 
        return 'null'
    
        

analyzer = Analyzer('C:/Users/esy2053/Documents/Lastline_report')
analyzer.Indikator4()
#sample = Sample('C:/Users/esy2053/Documents/Lastline_report/data (2).json')
#sample.report.checkReportForRegistry('CURRENTVERSION\RUN')
#[a-zA-Z].*\d+.*[a-zA-Z]\.exe


def suspiciousName(name):
    #exe several times 
    str = '.exe' 
    x = name.count(str)
    if x >= 2:
        return True
    #more than 4 ' ' in string
    str = ' '
    x = name.count(str)
    if x >= 4 :
        return True 
    return False 
    

#sample = Sample('C:/Users/esy2053/Documents/Lastline_report/rootkit.exe.json')
#x = ['xpsp2res.dll', 'cryptsp.dll', 'ntoskrnl.exe', 'jqs.exe']
#for subject in sample.report.analysis_subjects:
#    a = subject.indikatorFive(x)
#    if a == 'null':
#        continue
#    x.remove(a)
    
    
#for subject in sample.report.analysis_subjects:
#    subject.indikatorThree()
#x = sample.report.analysis_subjects[0]
#print(str(x))

    

        
        
#s = 'C:\\Windows'
#x = suspiciousName(s)
#print(str(x))











































