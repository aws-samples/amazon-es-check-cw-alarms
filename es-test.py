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

Given the name of an Amazon Elasticsearch Service cluster, create the set of recommended CloudWatch alarms.

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
clusterName       Amazon Elasticsearch Service domain name on which the alarms are to be created
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

# Defaults for parameters:
# env               environment; is used in the Alarm name only
# clusterName       Elasticsearch domain name
# alarmActions      list of SNS arns to be notified when the alarm is fired
env = 'Test'
domain = 'testcluster1'
account = "123456789012"
region = "us-west-2"
# WARNING!! The alarmActions can be hardcoded, to allow for easier standardization. BUT make sure they're what you want!
alarmActions = "['" + "arn:aws:sns:" + region + ":" + account + ":sendnotification']"

# Amazon Elasticsearch Service settings 
nameSpace = 'AWS/ES'    # set for these Amazon Elasticsearch Service alarms
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
    
esfreespace = 2048.0  # default amount of free space (in MB). ALSO minimum set by AWS ES
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
    parser = argparse.ArgumentParser(description = 'Create a set of recommended CloudWatch alarms for a given Amazon Elasticsearch Service domain.')  
    parser.add_argument('-n', '--notify', nargs='+',
        required = False, default=[],
        help = "List of CloudWatch alarm actions; e.g. ['arn:aws:sns:xxxx']")
    parser.add_argument("-e", "--env", required = True, type = str, default = "Test", 
        help = "Environment (e.g., Test, or Prod). Prepended to the alarm name.")
    parser.add_argument("-f", "--free", required = False, type = float, default=2000.0, help = "Minimum free storage (MB) on which to alarm")
    parser.add_argument("-p", "--profile", required = False, type = str, default='default',
        help = "IAM profile name to use")
    parser.add_argument("-c", "--cluster", required = False, type = str, help = "Amazon Elasticsearch Service domain name (e.g., testcluster1)")
    parser.add_argument("-r", "--region", required = False, type = str, default='us-east-1', help = "AWS region for the cluster.")
    
    if len(sys.argv) == 1:
        parser.error('Insufficient arguments provided. Exiting for safety.')
        logging.critical("Insufficient arguments provided. Exiting for safety.")
        sys.exit()
    args = parser.parse_args()
    # Reset minimum allowable, if less than AWS ES min
    if args.free < esfreespace:
        args.free = esfreespace
        
    #args.notify = ast.literal_eval(args.notify)
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
    env = args.env

    #parser = argparse.ArgumentParser()
    #parser.add_argument('-n', nargs='+',
    #    required = True, default=[],
    #    help = "List of CloudWatch alarm actions; e.g. ['arn:aws:sns:xxxx']")
    #parser.add_argument("-e", "--env", required = True, type = str, default = "Test", 
    #    help = "Environment (e.g., Test, or Prod). Prepended to the alarm name.")
    #parser.add_argument("-f", "--free", required = False, type = float, default=2000.0, help = "Minimum free storage (MB) on which to alarm")
    #parser.add_argument("-p", "--profile", required = False, type = str, default='default',
    #    help = "IAM profile name to use")
    #parser.add_argument("-c", "--cluster", required = False, type = str, help = "Amazon Elasticsearch Service domain name (e.g., testcluster1)")

    #args = parser.parse_args()
    #args = parser.parse_args(r'-d C:\blah C:\anotherBlah C:\anotherBlahBlah'.split())
    print(args)



