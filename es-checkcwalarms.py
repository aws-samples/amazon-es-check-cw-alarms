#!/usr/bin/env python
"""
Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License").
You may not use this file except in compliance with the License.
A copy of the License is located at

http://aws.amazon.com/apache2.0

or in the "license" file accompanying this file. This file is distributed
on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
express or implied. See the License for the specific language governing
permissions and limitations under the License.
------------------------------------------------------------------------------

Checks the alarms set up for each Elasticsearch domain in this region.
Can be run as a Lambda or as a standalone Python program.

Requires the following permissions:  
* ability to output Lambda operations messages to CloudWatch logs (logs:*) 
        Probably only need: logs:CreateLogGroup; logs:CreateLogStream, logs:PutLogEvents
* create CloudWatch alarms
        (per http://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/permissions-reference-cw.html )
        cloudwatch:DescribeAlarms
        cloudwatch:DescribeAlarmsForMetric
        cloudwatch:EnableAlarmActions | DisableAlarmActions (depending on options chosen)     	
        cloudwatch:PutMetricAlarm       
        
* ability to list Elasticsearch domains (es:ESHttpGet)
        (per http://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-configuration-api.html )
        es:ListDomainNames

This code can be run from the command line, or as a Lambda function.        
If run as a Lambda: expects the following environment variables: 
esprefix        string      prefix for AWS Elasticsearch domain names: only check that set of domains; e.g. 'test-'
region          string      region in which the Lambda is to be run
# WARNING!! The alarmActions can be hardcoded, to allow for easier standardization. BUT make sure they're what you want!
alarmActions    string      array of actions; e.g. '["arn:aws:sns:us-west-2:123456789012:sendnotification"]'

@author Veronika Megler
@date August 2017

"""
from __future__ import print_function # Python 2/3 compatibility

# https://www.npmjs.com/package/serverless-python-requirements
try:
 import unzip_requirements
except ImportError:
 pass 
 
# First: import standard modules
import string
import json
import time
from datetime import datetime
import sys
import os
import logging
import pprint
import boto3
import argparse
import collections

esfreespace = 2048.0  # default amount of free space (in MB). ALSO minimum set by AWS ES
esFreespacePercent = .20    # Recommended 20% free space
esprefix = ""
account = "123456789012"
region = "us-east-1"
# WARNING!! The alarmActions can be hardcoded, to allow for easier standardization. BUT make sure they're what you want!
alarmActions = ["arn:aws:sns:" + region + ":" + account + ":sendnotification"]

# AWS Elasticsearch settings 
nameSpace = 'AWS/ES'    # set for these AWS Elasticsearch alarms
# The following table must be updated when instance definitions change
# See: https://aws.amazon.com/elasticsearch-service/pricing/ , select your region
# Definitions are in GB
diskSpace = {"r3.large.elasticsearch": 32,
    "r3.xlarge.elasticsearch":	80,
    "r3.2xlarge.elasticsearch":	160,
    "r3.4xlarge.elasticsearch":	320,
    "r3.8xlarge.elasticsearch":	32,
    "m3.medium.elasticsearch":	4,
    "m3.large.elasticsearch":	32,
    "m3.xlarge.elasticsearch":	80,
    "m3.2xlarge.elasticsearch":	160, 
    "i2.xlarge.elasticsearch":	800,
    "i2.2xlarge.elasticsearch":	1600}

def get_args():
    """
    Parse command line arguments and populate args object.
    The args object is passed to functions as argument

    Returns:
        object (ArgumentParser): arguments and configuration settings
    """    
    parser = argparse.ArgumentParser(description = 'Checks a set of recommended CloudWatch alarms for Amazon Elasticsearch domains (optionally, those beginning with a given prefix).')  
    parser.add_argument("-e", "--esprefix", required = False, type = str, default = "", 
        help = "Only check AWS Elasticsearch domains that begin with this prefix.")
    parser.add_argument("-n", "--notify", required = False, type = str, default=alarmActions,
        help = "List of CloudWatch alarm actions; e.g. ['arn:aws:sns:xxxx']")
    # The following argument is used in the cases where free storage can't be calculated from known/acquirable info
    parser.add_argument("-f", "--free", required = False, type = float, default=esfreespace, help = "Minimum free storage (Mb) on which to alarm")
    parser.add_argument("-p", "--profile", required = False, type = str, default='default',
        help = "IAM profile name to use")

    parser.add_argument("-r", "--region", required = False, type = str, default='us-east-1', help = "AWS region for the domain. Default: us-east-1")

    args = parser.parse_args()
    args.prog = parser.prog
    # Reset minimum allowable, if less than AWS ES min
    if args.free < esfreespace:
        args.free = esfreespace
    return args

def convert_unicode(data):
    '''
    Takes a unicode input, and returns the same as utf-8
    '''
    if isinstance(data, basestring):
        return str(data)
    elif isinstance(data, collections.Mapping):
        return dict(map(convert_unicode, data.iteritems()))
    elif isinstance(data, collections.Iterable):
        return type(data)(map(convert_unicode, data))
    else:
        return data       
    
def get_domains_list(esclient, esprefix):    
    # Returns the list of Elasticsearch domains that start with this prefix
    domainNamesList = esclient.list_domain_names()
    # Get a list of the Elasticsearch domains we're interested in
    ourDomains = []
    for domain in domainNamesList['DomainNames']:
        name = domain['DomainName']
        #print(name)
        if name.startswith(esprefix):
            ourDomains.append(name)
    # Now we've got the list 
    return ourDomains


class ESDomain(object):
    '''
    This class represents the Amazon Elasticsearch domain
    '''
    
    def __init__(self, botoes, domain, wantesfree):
        self.domain = domain
        self.dedicatedMasters = False
        self.domainStats = None
        self.esfree = wantesfree      # Minimum free to allow, if no other info available
        self.warnings = []
        self.ebs = False
        self.kmsenabled = False
        # The following array specifies the alarms we wish to create for each AWS Elasticsearch domain.
        # We may need to reset some parameters per domain stats, so we reset it for each domain.
        # The stats are selected per the following documentation:
        #  http://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-managedomains.html#es-managedomains-cloudwatchmetrics
        # Array format:
        # (MetricName, Statistic, Period, EvaluationPeriods  [int], ComparisonOperator, Threshold [float] )
        #       ComparisonOperator: 'GreaterThanOrEqualToThreshold'|'GreaterThanThreshold'|'LessThanThreshold'|'LessThanOrEqualToThreshold'
        self.esAlarms = [
            ("ClusterStatus.yellow", "Maximum", 60, 5, "GreaterThanOrEqualToThreshold", 1.0 ),
            ("ClusterStatus.red",   "Maximum", 60, 5, "GreaterThanOrEqualToThreshold", 1.0 ),
            ("CPUUtilization", "Average", 60, 5, "GreaterThanOrEqualToThreshold", 80.0 ),
            ("JVMMemoryPressure", "Average", 60, 5, "GreaterThanOrEqualToThreshold", 85.0 ),
            ("ClusterIndexWritesBlocked", "Maximum", 60, 5, "GreaterThanOrEqualToThreshold", 1.0 )
            # OPTIONAL
            , ("AutomatedSnapshotFailure", "Maximum", 60, 5, "GreaterThanOrEqualToThreshold", 1.0 )        
            ]
           
        # First: get basic domain definition, and check options against best practices   
        self.get_domain_stats(botoes) 
        if self.domainStats == None:
            # For whatever reason, didn't get a response from this domain; FAIL.
            print("No domain results received from domain " + domain)
            return None    
        self.nodes_and_masters()
        self.log_publishing()
        
        if self.dedicatedMasters:
            # The following alarms apply for domains with dedicated master nodes.
            self.esAlarms.append(("MasterCPUUtilization", "Maximum", 60, 5, "GreaterThanOrEqualToThreshold", 80.0 ))
            self.esAlarms.append(("MasterJVMMemoryPressure", "Maximum", 60, 5, "GreaterThanOrEqualToThreshold", 80.0 ))
            self.esAlarms.append(("MasterReachableFromNode", "Maximum", 60, 5, "LessThanOrEqualToThreshold", 0.0 ))
            
        if self.kmsenabled:
            # The following alarms are available for domains with encryption at rest
            self.esAlarms.append(("KMSKeyError", "Maximum", 60, 5, "GreaterThanOrEqualToThreshold", 1.0 ))
            self.esAlarms.append(("KMSKeyInaccessible", "Maximum", 60, 5, "GreaterThanOrEqualToThreshold", 1.0 ))
        
        # Figure out how much storage the domain has, and should have 
        self.calc_storage()

        for warning in self.warnings:
            print(domain, "WARNING:", warning)
 
    def get_alarms(self):
        #print(str(self.esAlarms))
        return self.esAlarms
    
    def get_esfree(self):
        return self.esfree
 
    def get_domain_stats(self, botoes):
        # First: get the domain stats, and check the basic domain options against best practices
        # TO FIX: If get throttled on this call (beyond boto3 throttling recovery), wait and retry
        response = None
        domain = self.domain
        try:
            response = botoes.describe_elasticsearch_domain(DomainName=domain)
        except ClientError as e:
            #e.response['Error']['Code'] == ...
            print("Error on getting domain stats from " + str(domain) + str(e))
            return False
        domainStats = response['DomainStatus']
        self.esversion = domainStats["ElasticsearchVersion"]            
        self.domainStats = domainStats
        #print(str(response))
        print("=======================================================================================================")
        print("Starting checks for Elasticsearch domain {} , version is {}".format(domain, self.esversion))
        
        # VPC Endpoint
        if "VPCOptions" in domainStats:
            print(domain, "VPC: ", str(convert_unicode(domainStats["VPCOptions"]["VPCId"])), 
                "AZs:", str(convert_unicode(domainStats["VPCOptions"]["AvailabilityZones"])), 
                "subnets:", str(convert_unicode(domainStats["VPCOptions"]["SubnetIds"])), 
                " security groups:", str(convert_unicode(domainStats["VPCOptions"]["SecurityGroupIds"])))
        else:
            self.warnings.append("Not using VPC Endpoint")

        # Encryption at rest
        if "EncryptionAtRestOptions" in domainStats:
            print(domain, "EncryptionAtRestOptions: ", str(convert_unicode(domainStats["EncryptionAtRestOptions"]["Enabled"])), 
                "Key:", str(convert_unicode(domainStats["EncryptionAtRestOptions"]["KmsKeyId"])))
            self.kmsenabled = domainStats["EncryptionAtRestOptions"]["Enabled"]   
        else:
            self.warnings.append("Not using Encryption at Rest")
            
        endpoint = None
        if "Endpoint" in domainStats:
            endpoint = domainStats["Endpoint"]
        elif "Endpoints" in domainStats:
            endpoint = convert_unicode(domainStats["Endpoints"]["vpc"])
        print(domain, "Automated snapshot hour (UTC):", domainStats["SnapshotOptions"]['AutomatedSnapshotStartHour'])
        self.endpoint = endpoint

        # Zone Awareness
        if domainStats['ElasticsearchClusterConfig']['ZoneAwarenessEnabled'] != "True":
            self.warnings.append("Does not have Zone Awareness enabled")
          
        return True       

    def nodes_and_masters(self):    
        # Data nodes and Masters 
        clusterConfig = self.domainStats['ElasticsearchClusterConfig']  
        print(self.domain, "Instance configuration: " + str(clusterConfig['InstanceCount']) + " instances; type:" + str(clusterConfig['InstanceType']))
        if int(clusterConfig['InstanceCount']) % 2 == 1:
            self.warnings.append("Instance count is ODD. Best practice is for an even number of data nodes and zone awareness.")
        if clusterConfig['DedicatedMasterEnabled'] == "True":
            self.dedicatedMasters = True
            print(domain, clusterConfig['DedicatedMasterCount'], "masters; type:", clusterConfig['DedicatedMasterType'])
            if int(clusterConfig['DedicatedMasterCount']) % 2 == 0:
                self.warnings.append("Dedicated master count is even - risk of split brain.!!")
        else: 
            self.warnings.append("Does not have Dedicated Masters.")    

    def log_publishing(self):
        if "LogPublishingOptions" in self.domainStats:
            msg = ""
            logpub = self.domainStats["LogPublishingOptions"]
            if "INDEX_SLOW_LOGS" in logpub and "Enabled" in logpub["INDEX_SLOW_LOGS"]:
                msg = msg + "Index slow logs enabled: " + str(logpub["INDEX_SLOW_LOGS"]["Enabled"])
            if "SEARCH_SLOW_LOGS" in logpub and "Enabled" in logpub["SEARCH_SLOW_LOGS"]:
                msg = msg + "Search slow logs enabled: " + str(logpub["SEARCH_SLOW_LOGS"]["Enabled"])
            if msg == "":
                self.warnings.append("Neither index nor search slow logs are enabled.")
            else:
                print(self.domain, msg)
        else:
            self.warnings.append("Neither index nor search slow logs are enabled.")
            
    def calc_storage(self):
        domainStats = self.domainStats
        # Storage calculation. 
        ebs = False
        esfree = float(esfreespace)   # Set up a default min free space
        clusterConfig = domainStats['ElasticsearchClusterConfig']
        if 'EBSOptions' not in domainStats or domainStats['EBSOptions']['EBSEnabled'] == False:
            self.warnings.append("EBS not in use. Using instance storage only.")
            if clusterConfig['InstanceType'] in diskSpace:
                esfree = diskSpace[clusterConfig['InstanceType']] * 1024 * esFreespacePercent * clusterConfig['InstanceCount']
                print(self.domain, "Instance storage definition is:", diskSpace[clusterConfig['InstanceType']], "GB; free storage calced to:", esfree, "MB")
            else:
                # InstanceType not found in diskSpace. What's going on? (some instance types change to/from EBS, over time, it seems)
                self.warnings.append(clusterConfig['InstanceType'] + " not EBS, and definition of its diskspace is not available.")
        else:  
            ebsOptions = domainStats['EBSOptions']
            iops = "No Iops"
            if "Iops" in ebsOptions:
                iops = str(ebsOptions['Iops']) + " Iops"
            totalStorage = int(clusterConfig['InstanceCount']) * int(ebsOptions['VolumeSize']) * 1024   # Convert to MB
            print(self.domain, "EBS enabled:", ebsOptions['EBSEnabled'], "type:", ebsOptions['VolumeType'], "size (GB):", ebsOptions['VolumeSize'], iops, str(totalStorage), " total storage (MB)")
            ebs = True
            esfree = float(int(float(totalStorage) * esFreespacePercent))
        print(self.domain, "Desired free storage set to (in MB):", str(esfree)) 
        self.ebs = ebs
        self.esfree = esfree
        self.esAlarms.append( ("FreeStorageSpace", "Minimum", 60, 5, "LessThanOrEqualToThreshold", float(esfree) ) )
        return 

def process_alarms(esclient, cwclient, espref, wantesfree, account, alarmActions):        
    ourDomains = get_domains_list(esclient, espref)
    # Now we've got the list 
    print("List of Elasticsearch domains starting with given prefix (" + espref + "): " + str(ourDomains))

    # Now, get a list of the CloudWatch alarms, for each domain.
    # We could cut this list significantly if we knew the alarm-name-prefix would always be ... 
    # But, we don't, right now?
    # TO DO: so ... given that ... add pagination, in case there's too many alarms.

    for domain in ourDomains:
        # First: check the basic domain options against best practices
        esdomain = ESDomain(esclient, domain, wantesfree)
        esAlarms = esdomain.get_alarms()

        # Now, check the individual CloudWatch alarms
        # Unless you add the correct dimensions, the alarm will not correctly "connect" to the metric
        # How do you know what's correct? - at the bottom of http://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/es-metricscollected.html
        dimensions = [  {"Name": "DomainName", "Value": domain }, 
                        {"Name": "ClientId", "Value": str(account) }
                    ]  
        # Get the list of alarms that have been set. 
        for esAlarm in esAlarms:
            (alarmMetric, alarmStat, alarmPeriod, alarmEvalPeriod, alarmOperator, alarmThreshold) = esAlarm
            metricsList = cwclient.describe_alarms_for_metric(
                MetricName=alarmMetric,
                Namespace=nameSpace,
                Dimensions=dimensions                        
                )
            alarms = metricsList['MetricAlarms']
            #print(" ---- " + str(alarms))
            # check the alarm(s) we got back, to make sure they're the ones we want.
            if len(alarms) < 1:
                print(domain, "WARNING: Missing alarm!!", str(esAlarm))
            for alarm in alarms:
                #print("Found alarm: ", domain, alarm['AlarmName'], alarm['MetricName'], alarm['Statistic'], alarm['Period'], alarm['Threshold'], 
                #        alarm['EvaluationPeriods'], alarm['ComparisonOperator'], alarm['AlarmActions'])
                okAlarm = True
                # (MetricName, Statistic, Period, EvaluationPeriods  [int], ComparisonOperator, Threshold [float] )
                if alarm['Statistic'] != alarmStat:
                    print(domain, "Alarm: Statistic does not match:", alarm['AlarmName'], "Should be: ", alarmStat, "; is", alarm['Statistic'])
                    okAlarm = False
                if alarm['Period'] != alarmPeriod:
                    print(domain, "Alarm: Period does not match:", alarm['AlarmName'], "Should be: ", alarmPeriod,  "; is", alarm['Period'])
                    okAlarm = False
                if alarm['Threshold'] != alarmThreshold:
                    print(domain, "Alarm: Threshold does not match:", alarm['AlarmName'], "Should be: ",  alarmThreshold,  "; is", alarm['Threshold'])
                    okAlarm = False
                if alarm['EvaluationPeriods'] != alarmEvalPeriod:
                    print(domain, "Alarm: EvaluationPeriods does not match:", alarm['AlarmName'], "Should be: ", alarmEvalPeriod,  "; is", alarm['EvaluationPeriods'])
                    okAlarm = False
                if alarm['ComparisonOperator'] != alarmOperator:
                    print(domain, "Alarm: ComparisonOperator does not match:", alarm['AlarmName'], "Should be: ", alarmOperator,  "; is", alarm['ComparisonOperator'])
                    okAlarm = False
                if alarm['AlarmActions'] != alarmActions:
                    print(domain, "Alarm: AlarmActions does not match:", alarm['AlarmName'], "Should be: ", alarmActions,  "; is", alarm['AlarmActions'])
                    okAlarm = False  
                # Free storage alarm.
                if alarmMetric == 'FreeStorageSpace': 
                    esfree = esdomain.get_esfree()
                    if alarm['Threshold'] < esfree:
                        print(domain, "Alarm: MinimumFreeStorage", alarm['AlarmName'],"space of", alarm['Threshold'], " (is less than the desired free space of ", str(esfree), "MB")
                        okAlarm = False
                    #else:
                    #   print(domain, alarm['AlarmName'],"Free storage space alarm of", alarm['Threshold'], "is greater than the desired total storage space of ", str(esfree))
                        
                if okAlarm:
                    print(domain, "Alarm ok; definition matches.", alarm['AlarmName'], alarm['MetricName'])
                #print("")    
    print("Successfully finished processing!")


###############################################################################
# 
# MAIN
#
###############################################################################

def lambda_handler(event, context):
    """The Lambda function handler

    Args:
        event: The event passed by Lambda
        context: The context passed by Lambda

    """

    print('Received event:' + json.dumps(event))
    # Check environment variables
    espref = esprefix
    try:
        espref = os.environ['esprefix']
    except:
        pass    
    wantesfree = esfreespace
    try:
        wantesfree = os.environ['esfree']
    except:
        pass    
    account = boto3.client('sts').get_caller_identity().get('Account')
    esAlarmActions = alarmActions
    try:
        esAlarmActions = os.environ['alarmActions']
    except:
        pass 
 
    # Establish credentials
    session_var = boto3.session.Session()
    credentials = session_var.get_credentials()
    esregion = session_var.region_name or 'us-east-1'
    esregion = 'us-east-1'
    esclient = boto3.client("es")
    cwclient = boto3.client("cloudwatch")

    process_alarms(esclient, cwclient, espref, wantesfree, account, esAlarmActions)
    return 'Success' 


# Standalone harness, to run the same checks from the command line    
if __name__ == "__main__":
    tmStart = datetime.utcnow()
    args = get_args()
    # Establish credentials
    account = boto3.client('sts').get_caller_identity().get('Account')
    b3session = boto3.Session(profile_name=args.profile, region_name=args.region)
    print("Starting ... at {}, account {} for prefix {} in region {} using IAM profile {}".format(tmStart, account, args.esprefix, args.region, args.profile))
    esclient = b3session.client("es")
    cwclient = b3session.client("cloudwatch")
    process_alarms(esclient, cwclient, args.esprefix, args.free, account, args.notify)
    
