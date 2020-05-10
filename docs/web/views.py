from django.http import HttpResponse
from django.shortcuts import render
from django.urls import reverse
from django.views import generic
from django import template
from django.core.files.storage import FileSystemStorage
from django.conf import settings

import uuid
import os
import xml.etree.ElementTree as ET
from docx import Document

def generate_report(scanxml):
    report_root = ET.parse(scanxml).getroot()

    report = Document()
    report.add_heading('BLUESPAWN Host Compromise Analysis Report (HCAR)', 0)

    # Parse XML File
    detections = list(report_root.iterfind('hunt/detection'))
    detections_files = []
    detections_registry = []
    detections_processes = []
    detections_eventlogs = []
    file_cnt = 0
    registry_cnt = 0
    process_cnt = 0
    eventlog_cnt = 0
    for detection in detections:
        if detection.get('type') == 'File':
            file_cnt += 1
            detections_files.append([
                detection.find('path').text if detection.find('path') is not None else "N/A", 
                detection.find('size').text if detection.find('size') is not None else "N/A", 
                detection.find('md5').text if detection.find('md5') is not None else "N/A", 
                detection.find('sha1').text if detection.find('sha1') is not None else "N/A", 
                detection.find('sha256').text if detection.find('sha256') is not None else "N/A"
            ])
        elif detection.get('type') == 'Registry':
            registry_cnt += 1
            detections_registry.append([
                detection.find('key').text if detection.find('key') is not None else "N/A", 
                detection.find('value').text if detection.find('value') is not None else "N/A", 
                detection.find('data').text if detection.find('data') is not None else "N/A"
            ]) 
        elif detection.get('type') == 'Process':
            process_cnt += 1
            detections_processes.append([
                detection.find('path').text if detection.find('path') is not None else "N/A", 
                detection.find('cmdline').text if detection.find('cmdline') is not None else "N/A", 
                detection.find('username').text if detection.find('username') is not None else "N/A"
            ]) 
        elif detection.get('type') == 'Event':
            eventlog_cnt += 1
            detections_eventlogs.append([
                detection.find('id').text if detection.find('id') is not None else "N/A", 
                detection.find('channel').text if detection.find('channel') is not None else "N/A"
            ]) 

    # MITRE ATT&CK IDs Table


    # Indicators of Attack
    report.add_heading('Indicators of Attack (IOAs)', level=1)
    report.add_heading('Files (%i)' % file_cnt, level=2)
    if file_cnt > 0:
        file_table = report.add_table(rows=1, cols=2, style='Table Grid')
        file_table_header = file_table.rows[0].cells
        file_table_header[0].text = 'Filename:'
        file_table_header[1].text = 'Details:'
        for item in detections_files:
            r = file_table.add_row().cells
            r[0].text = str(item[0])
            r[1].text = ('Size: ' + str(item[1]) + '\nMD5: ' + str(item[2]) + 
                '\nSHA1: ' + str(item[3]) + '\nSHA256: ' + str(item[4]))

    report.add_heading('Registry (%i)' % registry_cnt, level=2)
    if registry_cnt > 0:
        registry_table = report.add_table(rows=1, cols=3, style='Table Grid')
        registry_table_header = registry_table.rows[0].cells
        registry_table_header[0].text = 'Key:'
        registry_table_header[1].text = 'Value:'
        registry_table_header[2].text = 'Data:'
        for item in detections_registry:
            r = registry_table.add_row().cells
            r[0].text = str(item[0])
            r[1].text = str(item[1])
            r[2].text = str(item[2])
    
    report.add_heading('Processes (%i)' % process_cnt, level=2)
    if process_cnt > 0:
        process_table = report.add_table(rows=1, cols=3, style='Table Grid')
        process_table_header = process_table.rows[0].cells
        process_table_header[0].text = 'Path:'
        process_table_header[1].text = 'Command Line:'
        process_table_header[2].text = 'Username:'
        for item in detections_processes:
            r = process_table.add_row().cells
            r[0].text = str(item[0])
            r[1].text = str(item[1])
            r[2].text = str(item[2])
    
    report.add_heading('Event Logs (%i)' % eventlog_cnt, level=2)
    if eventlog_cnt > 0:
        eventlog_table = report.add_table(rows=1, cols=3, style='Table Grid')
        eventlog_table_header = eventlog_table.rows[0].cells
        eventlog_table_header[0].text = 'ID:'
        eventlog_table_header[1].text = 'Channel:'
        eventlog_table_header[2].text = 'Information:'
        for item in detections_eventlogs:
            r = eventlog_table.add_row().cells
            r[0].text = str(item[0])
            r[1].text = str(item[1])
    

    report_name = str(uuid.uuid4()) + '.docx'
    report.save(os.path.join(getattr(settings, 'BASE_DIR'), 'media/scans/' + report_name))

    return report_name

def UploadScanView(request):
    if request.method == 'POST' and request.FILES['scanxml']:
        scan = request.FILES['scanxml']
        fs = FileSystemStorage()
        ext = scan.name.split('.')[-1]
        filename = "%s.%s" % (uuid.uuid4(), ext)

        if ext != 'xml':
            return HttpResponse(status=415)

        upload = fs.save('scans/' + filename, scan)

        #try:
        report_name = generate_report(os.path.join(getattr(settings, 'BASE_DIR'), 'media/scans/' + filename))
        return render(request, 'report.html', {
            'generated_report_url' : report_name
        })
        #except:
        #    return HttpResponse(status=500)

    return render(request, 'report.html')

