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

Given the name of an Elasticsearch cluster, create the set of recommended CloudWatch alarms.

Naming convention for the alarms are: {Environment}-{domain}-{MetricName}-alarm

Requires the following permissions:  
* create CloudWatch alarms
        (per http://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/permissions-reference-cw.html )
        cloudwatch:DescribeAlarms
        cloudwatch:DescribeAlarmsForMetric
        cloudwatch:EnableAlarmActions | DisableAlarmActions (depending on options chosen)     	
        cloudwatch:PutMetricAlarm       
        ... The managed policy CloudWatchFullAccess provides the needed permissions.        

* To check that free space is appropriately defined, also need to be able to check the E/S cluster definitions.

        
Expects the following parameters:
env               environment; is used in the Alarm name only. Default: Test
clusterName       AWS Elasticsearch domain name on which the alarms are to be created
clientId          the account Id of the owning AWS account (needed for CloudWatch alarm dimension)
alarmActions      list of SNS arns to be notified when the alarm is fired 
free              minimum amount of free storage to assign, if no other information is available

@author Veronika Megler
@date August 2017

"""

from __future__ import print_function # Python 2/3 compatibility

# Need to: pip install elasticsearch; boto3; requests_aws4auth; requests?
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
import ast

# Defaults for parameters:
# env               environment; is used in the Alarm name only
# clusterName       Elasticsearch domain name
# alarmActions      list of SNS arns to be notified when the alarm is fired
env = 'Test'
domain = 'testcluster1'
account = "123456789012"
# WARNING!! The alarmActions can be hardcoded, to allow for easier standardization. BUT make sure they're what you want!
alarmActions = ["arn:aws:sns:us-west-2:123456789012:sendnotification"]

# AWS Elasticsearch settings 
nameSpace = 'AWS/ES'    # set for these AWS Elasticsearch alarms
# The following table must be updated when instance definitions change
# See: https://aws.amazon.com/elasticsearch-service/pricing/ , select your region
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
esfreespace = 2000.0  # default amount of free space (in MB)
esFreespacePercent = .20    # Recommended 20% free space    
#logger = logging.getLogger()
#logger.setLevel(print)
#logging.basicConfig(format='%(asctime)s app=' + esapp + ' %(levelname)s:%(name)s %(message)s',level=print)

def get_args():
    """
    Parse command line arguments and populate args object.
    The args object is passed to functions as argument

    Returns:
        object (ArgumentParser): arguments and configuration settings
    """
    parser = argparse.ArgumentParser(description = 'Create a set of recommended CloudWatch alarms for a given AWS Elasticsearch cluster.')  
    parser.add_argument("-c", "--cluster", required = True, type = str, help = "AWS Elasticsearch cluster name (e.g., testcluster1)")
    #parser.add_argument("-a", "--account", required = True, type = int, help = "AWS account id of the owning account (needed for metric dimension).")
    parser.add_argument("-e", "--env", required = False, type = str, default = "Test", 
        help = "Environment (e.g., Test, or Prod). Prepended to the alarm name.")
    parser.add_argument("-n", "--notify", required = False, type = str, default=alarmActions,
        help = "List of CloudWatch alarm actions; e.g. ['arn:aws:sns:xxxx']")
    # The following argument should be removed (TO DO) once we calculate free storage required based on cluster size for instance storage too
    parser.add_argument("-f", "--free", required = False, type = float, default=2000.0, help = "Minimum free storage (Mb) on which to alarm")
    parser.add_argument("-p", "--profile", required = False, type = str, default='default',
        help = "IAM profile name to use")

    parser.add_argument("-r", "--region", required = False, type = str, default='us-east-1', help = "AWS region for the cluster.")
    
    if len(sys.argv) == 1:
        parser.error('Insufficient arguments provided. Exiting for safety.')
        logging.critical("Insufficient arguments provided. Exiting for safety.")
        sys.exit()
    args = parser.parse_args()
    args.notify = ast.literal_eval(args.notify)
    args.prog = parser.prog
    return args

###############################################################################
# 
# MAIN
#
###############################################################################    
if __name__ == "__main__":
    tmStart = datetime.utcnow()
    print("Starting ... at {}".format(tmStart))
    args = get_args()
    #logging.basicConfig(filename = args.logfile, format = '%(asctime)s %(levelname)s %(message)s', level = LOG_LEVEL)    
    # Establish credentials
    account = boto3.client('sts').get_caller_identity().get('Account')
    b3session = boto3.Session(profile_name=args.profile, region_name=args.region)
    domain = args.cluster

    # Get current account id: BUT, would need that STS access. Making it a parameter instead reduces the privileges required
    #print(boto3.client('sts').get_caller_identity()['Account'])
    
    # Calculate the amount of storage the free space alarm requires
    esclient = b3session.client("es")
    response = esclient.describe_elasticsearch_domain(DomainName=domain)
    domainStats = response['DomainStatus']
    clusterConfig = domainStats['ElasticsearchClusterConfig'] 
    #print(str(response))
    esfree = float(args.free)   # Reset to default
    ebs = False
    if 'EBSOptions' not in domainStats or domainStats['EBSOptions']['EBSEnabled'] == False:
        self.warnings.append("EBS not in use. Using instance storage only.")
        if clusterConfig['InstanceType'] in diskSpace:
            esfree = diskSpace[clusterConfig['InstanceType']] * 1024 * esFreespacePercent * clusterConfig['InstanceCount']
            print("Instance storage definition is:", diskSpace[clusterConfig['InstanceType']], "; free storage calced to:", esfree)
        else:
            # InstanceType not found in diskSpace. What's going on? (some instance types change to/from EBS, over time, it seems)
            print(clusterConfig['InstanceType'] + " not EBS, and definition of its diskspace is not available.")
    else:  
        ebsOptions = domainStats['EBSOptions']
        iops = "No Iops"
        if "Iops" in ebsOptions:
            iops = str(ebsOptions['Iops']) + " Iops"
        totalStorage = int(clusterConfig['InstanceCount']) * int(ebsOptions['VolumeSize']) * 1024   # Convert to MB
        print("EBS enabled:", ebsOptions['EBSEnabled'], "type:", ebsOptions['VolumeType'], "size (GB):", ebsOptions['VolumeSize'], iops, str(totalStorage), " total storage (MB)")
        ebs = True
        esfree = float(int(float(totalStorage) * esFreespacePercent))
    print("Desired free storage set to (in MB):", str(esfree)) 
    
    # The following array specifies the statistics we wish to create for each AWS Elasticsearch cluster. 
    # The stats are selected per the following documentation:
    #  http://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-managedomains.html#es-managedomains-cloudwatchmetrics
    # Array format:
    # (MetricName, Statistic, Period, EvaluationPeriods  [int], ComparisonOperator, Threshold [float] )
    #       ComparisonOperator: 'GreaterThanOrEqualToThreshold'|'GreaterThanThreshold'|'LessThanThreshold'|'LessThanOrEqualToThreshold'
    esAlarms = [
        ("ClusterStatus.yellow", "Maximum", 60, 5, "GreaterThanOrEqualToThreshold", 1.0 ),
        ("ClusterStatus.red",   "Maximum", 60, 5, "GreaterThanOrEqualToThreshold", 1.0 ),
        ("CPUUtilization", "Average", 60, 5, "GreaterThanOrEqualToThreshold", 80.0 ),
        ("JVMMemoryPressure", "Average", 60, 5, "GreaterThanOrEqualToThreshold", 85.0 ),
        ("FreeStorageSpace", "Minimum", 60, 5, "LessThanOrEqualToThreshold", float(esfree) ),
        ("ClusterIndexWritesBlocked", "Maximum", 60, 5, "GreaterThanOrEqualToThreshold", 1.0 )
        # OPTIONAL
        , ("AutomatedSnapshotFailure", "Maximum", 60, 5, "GreaterThanOrEqualToThreshold", 1.0 )        
        ]
        
    # The following alarms apply for systems with dedicated master nodes.
    if domainStats['ElasticsearchClusterConfig']['DedicatedMasterEnabled'] == "True":
        esAlarms.append(("MasterCPUUtilization", "Maximum", 60, 5, "GreaterThanOrEqualToThreshold", 80.0 ))
        # The following doesn't seem to show up in CloudWatch metrics. Why?
        esAlarms.append(("MasterJVMMemoryPressure", "Maximum", 60, 5, "GreaterThanOrEqualToThreshold", 80.0 ))
            
    # Unless you add the correct dimensions, the alarm will not correctly "connect" to the metric
    # How do you know what's correct? - at the bottom of http://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/es-metricscollected.html
    dimensions = [  {"Name": "DomainName", "Value": domain }, 
                    {"Name": "ClientId", "Value": str(account) }
                ]
    #cwclient = boto3.client("cloudwatch", region_name=esregion)
    cwclient = b3session.client("cloudwatch")

    # For each alarm in the list, create a CloudWatch alarm            
    for esAlarm in esAlarms:
        (alarmMetric, alarmStat, alarmPeriod, alarmEvalPeriod, alarmOperator, alarmThreshold) = esAlarm
        alarmName = '-'.join([env, 'Elasticsearch', domain, alarmMetric, 'Alarm'])
        print("Creating ", alarmName)
        #print(str(esAlarm))
        
        response = cwclient.put_metric_alarm(
            AlarmName=alarmName,
            AlarmDescription=alarmName,
            #ActionsEnabled=True|False,
            #OKActions=['string'],
            AlarmActions= args.notify,
            #InsufficientDataActions=['string'],
            MetricName=alarmMetric,
            Namespace=nameSpace,
            Statistic=alarmStat,
            #ExtendedStatistic='string',
            Dimensions=dimensions,
            Period=alarmPeriod,
            #Unit='Seconds'|'Microseconds'|'Milliseconds'|'Bytes'|'Kilobytes'|'Megabytes'|'Gigabytes'|'Terabytes'|'Bits'|'Kilobits'|'Megabits'|'Gigabits'|'Terabits'|'Percent'|'Count'|'Bytes/Second'|'Kilobytes/Second'|'Megabytes/Second'|'Gigabytes/Second'|'Terabytes/Second'|'Bits/Second'|'Kilobits/Second'|'Megabits/Second'|'Gigabits/Second'|'Terabits/Second'|'Count/Second'|'None',
            EvaluationPeriods=alarmEvalPeriod,
            Threshold=alarmThreshold,
            ComparisonOperator=alarmOperator
            #TreatMissingData='string',
            #EvaluateLowSampleCountPercentile='string'
        )
    
    print("Successfully finished creating alarms!")


