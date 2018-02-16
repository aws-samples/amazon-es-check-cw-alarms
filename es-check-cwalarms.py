#!/usr/bin/env python
"""
Checks the alarms set up for each Amazon Elasticsearch Service domain in this region.
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
DEFAULT_DOMAIN_PREFIX        string      prefix for Amazon Elasticsearch Service domain names: only check that set of domains; e.g. 'test-'
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
import traceback
import boto3
import argparse
import collections

MIN_ES_FREESPACE = 2048.0  # default amount of free space (in MB). ALSO minimum set by AWS ES
ES_FREESPACE_PERCENT = .20    # Recommended 20% free space
DEFAULT_ES_FREESPACE = MIN_ES_FREESPACE

DEFAULT_DOMAIN_PREFIX = ""
DEFAULT_REGION = 'us-east-1'
DEFAULT_SNSTOPIC = 'sendnotification'
DEFAULT_ENVIRONMENT = 'Test'
AWS_REGION = DEFAULT_REGION

Alarm = collections.namedtuple('Alarm', ['metric', 'stat', 'period',  'evalPeriod', 'operator', 'threshold', 'alarmAction'])

# Amazon Elasticsearch Service settings 
ES_NAME_SPACE = 'AWS/ES'    # set for these Amazon ES alarms
# Amazon Elasticsearch Service settings 
ES_NAME_SPACE = 'AWS/ES'    # set for these Amazon Elasticsearch Service alarms
# The following table lists instance types with instance storage, for free storage calculations. 
# It must be updated when instance definitions change
# See: https://aws.amazon.com/elasticsearch-service/pricing/ , select your region
# Definitions are in GB
DISK_SPACE = {"r3.large.elasticsearch": 32,
    "r3.xlarge.elasticsearch":	80,
    "r3.2xlarge.elasticsearch":	160,
    "r3.4xlarge.elasticsearch":	320,
    "r3.8xlarge.elasticsearch":	640,
    "m3.medium.elasticsearch":	4,
    "m3.large.elasticsearch":	32,
    "m3.xlarge.elasticsearch":	80,
    "m3.2xlarge.elasticsearch":	160, 
    "i2.xlarge.elasticsearch":	800,
    "i2.2xlarge.elasticsearch":	1600,
    "i3.large.elasticsearch":   475,
    "i3.xlarge.elasticsearch":  950,
    "i3.2xlarge.elasticsearch": 1900,
    "i3.4xlarge.elasticsearch": 3800,
    "i3.8xlarge.elasticsearch": 7600,
    "i3.16xlarge.elasticsearch": 15200
    }

LOG_LEVELS = {'CRITICAL': 50, 'ERROR': 40, 'WARNING': 30, 'INFO': 20, 'DEBUG': 10}

def init_logging():
    # Setup logging because debugging with print can get ugly.
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    logging.getLogger("boto3").setLevel(logging.WARNING)
    logging.getLogger('botocore').setLevel(logging.WARNING)
    logging.getLogger('nose').setLevel(logging.WARNING)
    logging.Formatter.converter = time.gmtime

    return logger

def setup_local_logging(logger, log_level = 'INFO'):
    # Set the Logger so if running locally, it will print out to the main screen.
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        '%(asctime)s %(name)-12s %(levelname)-8s %(message)s',datefmt='%Y-%m-%dT%H:%M:%SZ'
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    if log_level in LOG_LEVELS:
        logger.setLevel(LOG_LEVELS[log_level])
    else:
        logger.setLevel(LOG_LEVELS['INFO'])

    return logger

def set_log_level(logger, log_level = 'INFO'):
    # There is some stuff that needs to go here.
    if log_level in LOG_LEVELS:
        logger.setLevel(LOG_LEVELS[log_level])
    else:
        logger.setLevel(LOG_LEVELS['INFO'])

    return logger
    
def get_default_alarm_actions(region, account, snstopic):
    # A default alarmActions can be hardcoded, to allow for easier standardization. BUT make sure it's what you want!
    alarmActions = ["arn:aws:sns:" + str(region) + ":" + str(account) + ":" + str(snstopic)]
    return alarmActions 

def get_args():
    """
    Parse command line arguments and populate args object.
    The args object is passed to functions as argument

    Returns:
        object (ArgumentParser): arguments and configuration settings
    """   
    parser = argparse.ArgumentParser(description = 'Create a set of recommended CloudWatch alarms for a given Amazon Elasticsearch Service domain.')  
    parser.add_argument('-n', '--notify', nargs='+', required = False, default=[],
        help = "List of CloudWatch alarm actions; e.g. ['arn:aws:sns:xxxx']")
    parser.add_argument("-e", "--esprefix", required = False, type = str, default = "", 
        help = "Only check AWS Elasticsearch domains that begin with this prefix.")
    parser.add_argument("-f", "--free", required = False, type = float, default=DEFAULT_ES_FREESPACE, help = "Minimum free storage (MB) on which to alarm")
    parser.add_argument("-p", "--profile", required = False, type = str, default='default',
        help = "IAM profile name to use")
    parser.add_argument("-r", "--region", required = False, type = str, default='us-east-1', help = "AWS region for the domain. Default: " + DEFAULT_REGION)

    args = parser.parse_args()
    args.prog = parser.prog
    try:
        args.account = boto3.client('sts').get_caller_identity().get('Account')   
    except Exception as e:     # e.g.: botocore.exceptions.EndpointConnectionError
        logger.critical(str(e))
        logger.critical("Exiting.")
        sys.exit()
    # Reset minimum allowable, if less than AWS ES min
    if args.free < MIN_ES_FREESPACE:
        logger.info("Freespace of " + args.free + " is less than the minimum for AES of " + MIN_ES_FREESPACE + ". Setting to " + MIN_ES_FREESPACE)
        args.free = MIN_ES_FREESPACE
    if args.notify == []:
        args.notify = get_default_alarm_actions(args.region,args.account,DEFAULT_SNSTOPIC) 
    logger.info("Starting at " + str(datetime.utcnow()) + ". Using parameters: " + str(args))
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
    #else:
    return data       

def str_convert_unicode(data):   
    return str(convert_unicode(data))
      
def get_domains_list(esclient, domainprefix):    
    # Returns the list of Elasticsearch domains that start with this prefix
    domainNamesList = esclient.list_domain_names()
    names = map(lambda domain: domain['DomainName'], domainNamesList['DomainNames'])
    return [name for name in names if name.startswith(domainprefix)]

class AlarmChecker(object):
  # Check the details of alarm, against expected values for this esAlarm
  # Alarm(MetricName, Statistic, Period, EvaluationPeriods  [int], ComparisonOperator, Threshold [float], AlarmActions )
  def __init__(self, domain, alarm):
    self.alarm = alarm
    self.domain = domain

  def check_statistics(self, expected_value):
    return self._check_field('Statistic', expected_value)

  def check_period(self, expected_value):
    return self._check_field('Period', expected_value)    

  def check_evalPeriod(self, expected_value):
    return self._check_field('EvaluationPeriods', expected_value)

  def check_operator(self, expected_value):
    return self._check_field('ComparisonOperator', expected_value)

  def check_threshold(self, expected_value):
    return self._check_field('Threshold', expected_value)

  def check_alarm_actions(self, expected_value):
    return self._check_field('AlarmActions', expected_value)

  def _check_field(self, field_name, expected_value):
    actual_value = self.alarm[field_name] 
    is_alarm_okay = actual_value == expected_value
    if not is_alarm_okay:
        logger.warning(' '.join([self.domain, "Alarm:", field_name, "does not match for", self.alarm['AlarmName'], "Should be:", str(expected_value), "but is", str(actual_value)]))
    return is_alarm_okay
    
class ESDomain(object):
    '''
    This class represents the Amazon Elasticsearch Service domain
    '''
    
    def __init__(self, botoes, domain, desiredEsFree, theAlarmAction):
        self.domain = domain
        self.dedicatedMasters = False
        self.esfree = desiredEsFree      # Minimum free to allow, if no other info available
        self.ebs = False
        self.kmsenabled = False
        # The following array specifies the alarms we wish to create for each Amazon ES domain.
        # We may need to reset some parameters per domain stats, so we reset it for each domain.
        # The stats are selected per the following documentation:
        #  http://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-managedomains.html#es-managedomains-cloudwatchmetrics
        # Array format:
        # (MetricName, Statistic, Period, EvaluationPeriods  [int], ComparisonOperator, Threshold [float] )
        #       ComparisonOperator: 'GreaterThanOrEqualToThreshold'|'GreaterThanThreshold'|'LessThanThreshold'|'LessThanOrEqualToThreshold'
        self.esAlarms = [
            Alarm(metric='ClusterStatus.yellow', stat='Maximum', period=60, evalPeriod=5, operator='GreaterThanOrEqualToThreshold', threshold=1.0, alarmAction=theAlarmAction),
            Alarm(metric='ClusterStatus.red', stat='Maximum', period=60, evalPeriod=5, operator='GreaterThanOrEqualToThreshold', threshold=1.0, alarmAction=theAlarmAction),
            Alarm(metric='CPUUtilization', stat='Average', period=60, evalPeriod=5, operator='GreaterThanOrEqualToThreshold', threshold=80.0, alarmAction=theAlarmAction),
            Alarm(metric='JVMMemoryPressure', stat='Average', period=60, evalPeriod=5, operator='GreaterThanOrEqualToThreshold', threshold=85.0, alarmAction=theAlarmAction),
            Alarm(metric='ClusterIndexWritesBlocked', stat='Maximum', period=60, evalPeriod=5, operator='GreaterThanOrEqualToThreshold', threshold=1.0, alarmAction=theAlarmAction)
            # OPTIONAL
            , Alarm(metric='AutomatedSnapshotFailure', stat='Maximum', period=60, evalPeriod=5, operator='GreaterThanOrEqualToThreshold', threshold=1.0, alarmAction=theAlarmAction)             
            ]
           
        # For other checks: get basic domain definition, and check options against best practices  
        try:
            self.get_domain_stats(botoes)
        except:
            self.domainStatus = None
            # For whatever reason, didn't get a response from this domain; return the default alarms.
            logger.error("No domainStatus response received from domain " + domain + "; no best practices checks performed; not all alarms created")
            raise   
        
        # Figure out how much storage the domain has, and should have 
        self.esAlarms.append(Alarm(metric="FreeStorageSpace", stat="Minimum", period=60, evalPeriod=5, 
            operator="LessThanOrEqualToThreshold", threshold=float(self.calc_storage()), alarmAction=theAlarmAction ) )
        
        if self.dedicatedMasters:
            # The following alarms apply for domains with dedicated master nodes.
            self.esAlarms.append(Alarm(metric='MasterCPUUtilization', stat='Maximum', period=60, evalPeriod=5, operator='GreaterThanOrEqualToThreshold', threshold=80.0, alarmAction=theAlarmAction))
            self.esAlarms.append(Alarm(metric='MasterJVMMemoryPressure', stat='Maximum', period=60, evalPeriod=5, operator='GreaterThanOrEqualToThreshold', threshold=80.0, alarmAction=theAlarmAction))
            self.esAlarms.append(Alarm(metric='MasterReachableFromNode', stat='Maximum', period=60, evalPeriod=5, operator='LessThanOrEqualToThreshold', threshold=0.0, alarmAction=theAlarmAction))
 
        if self.kmsenabled:
            # The following alarms are available for domains with encryption at rest
            self.esAlarms.append(Alarm(metric='KMSKeyError', stat='Maximum', period=60, evalPeriod=5, operator='GreaterThanOrEqualToThreshold', threshold=1.0, alarmAction=theAlarmAction))
            self.esAlarms.append(Alarm(metric='KMSKeyInaccessible', stat='Maximum', period=60, evalPeriod=5, operator='GreaterThanOrEqualToThreshold', threshold=1.0, alarmAction=theAlarmAction))
            
        return
        
    def get_alarms(self):
        return self.esAlarms
    
    def get_esfree(self):
        return self.esfree

    def check_vpc_options(self):
        # VPC Endpoint
        if "VPCOptions" in self.domainStatus:
            vpcOptions = self.domainStatus["VPCOptions"] 
            logger.info(' '.join([self.domain, "VPC:", str_convert_unicode(vpcOptions["VPCId"]), 
                "AZs:", str_convert_unicode(vpcOptions["AvailabilityZones"]), 
                "subnets:", str_convert_unicode(vpcOptions["SubnetIds"]), 
                " security groups:", str_convert_unicode(vpcOptions["SecurityGroupIds"])]))
        else:
            logger.warning(self.domain + " Not using VPC Endpoint")
        return

    def check_encryption_at_rest(self):
        # Encryption at rest
        is_encryption_enabled = 'EncryptionAtRestOptions' in self.domainStatus and self.domainStatus['EncryptionAtRestOptions']['Enabled']
        if is_encryption_enabled:
            encryptionAtRestOptions = self.domainStatus["EncryptionAtRestOptions"]
            self.kmsenabled = encryptionAtRestOptions["Enabled"] 
            logger.info(' '.join([self.domain, "EncryptionAtRestOptions: ", str_convert_unicode(encryptionAtRestOptions["Enabled"]), 
                "Key:", str_convert_unicode(encryptionAtRestOptions["KmsKeyId"])]))  
        else:
            logger.warning(self.domain + " Not using Encryption at Rest") 
        return
    
    def check_endpoint(self):
        endpoint = None
        if "Endpoint" in self.domainStatus:
            endpoint = self.domainStatus["Endpoint"]
        elif "Endpoints" in self.domainStatus:
            endpoint = convert_unicode(self.domainStatus["Endpoints"]["vpc"])
        self.endpoint = endpoint
        logger.info(self.domain + " endpoint: " + str(endpoint)) 
        return
        
    def get_domain_stats(self, botoes):
        # First: get the domain stats, and check the basic domain options against best practices
        # TO FIX: If get throttled on this call (beyond boto3 throttling recovery), wait and retry
        response = None
        domain = self.domain
        try:
            response = botoes.describe_elasticsearch_domain(DomainName=domain)
        except ClientError as e:
            logger.error("Error on getting domain stats from " + str(domain) + str(e))
            raise e
        domainStatus = response['DomainStatus']
        self.esversion = domainStatus["ElasticsearchVersion"]            
        self.domainStatus = domainStatus
        logger.info("=======================================================================================================")
        logger.info("Starting checks for Amazon Elasticsearch Service domain {}, version is {}".format(domain, self.esversion))
        self.check_endpoint()        
        self.check_vpc_options()
        self.check_encryption_at_rest()
        
        # Zone Awareness
        if not domainStatus['ElasticsearchClusterConfig']['ZoneAwarenessEnabled']:
            logger.warning(domain + " Does not have Zone Awareness enabled")
        else:
            logger.info(domain + " Has Zone Awareness enabled")        
        self.nodes_and_masters()
        self.log_publishing()
        
        logger.info(' '.join([domain, "Automated snapshot hour (UTC):", str(self.domainStatus["SnapshotOptions"]['AutomatedSnapshotStartHour'])]))        
       
        return       

    def nodes_and_masters(self):    
        # Data nodes and Masters 
        clusterConfig = self.domainStatus['ElasticsearchClusterConfig']  
        logger.info(self.domain + " Instance configuration: " + str(clusterConfig['InstanceCount']) + " instances; type: " + str(clusterConfig['InstanceType']))
        if int(clusterConfig['InstanceCount']) % 2 == 1:
            logger.warning(self.domain + " Instance count is ODD. Best practice is for an even number of data nodes and zone awareness.")
        if clusterConfig['DedicatedMasterEnabled']:
            self.dedicatedMasters = True
            logger.info(' '.join([self.domain, str(clusterConfig['DedicatedMasterCount']), "masters; type:", clusterConfig['DedicatedMasterType']]))
            if int(clusterConfig['DedicatedMasterCount']) % 2 == 0:
                logger.warning(self.domain + " Dedicated master count is even - risk of split brain.!!")
        else: 
            logger.warning(self.domain + " Does not have Dedicated Masters." + str(clusterConfig['DedicatedMasterEnabled']))
        return

    def log_publishing(self):
        if "LogPublishingOptions" in self.domainStatus:
            msg = ""
            logpub = self.domainStatus["LogPublishingOptions"]
            if "INDEX_SLOW_LOGS" in logpub and "Enabled" in logpub["INDEX_SLOW_LOGS"]:
                msg += "Index slow logs enabled: " + str(logpub["INDEX_SLOW_LOGS"]["Enabled"]) + ". "
            if "SEARCH_SLOW_LOGS" in logpub and "Enabled" in logpub["SEARCH_SLOW_LOGS"]:
                msg += "Search slow logs enabled: " + str(logpub["SEARCH_SLOW_LOGS"]["Enabled"])
            if msg == "":
                logger.info(self.domain + " Neither index nor search slow logs are enabled.")
            else:
                logger.info(self.domain + ' ' + msg)
        else:
            logger.info(self.domain + " Neither index nor search slow logs are enabled.")
        return
        
    def calc_storage(self):
        ebs = False
        es_freespace = float(MIN_ES_FREESPACE)   # Set up a default min free space
        if self.domainStatus == None:
            logger.warning("No domain statistics available; using default for minimum storage.")
            return es_freespace
        domainStatus = self.domainStatus
        
        # Storage calculation. 
        clusterConfig = domainStatus['ElasticsearchClusterConfig']        
        is_ebs_enabled = 'EBSOptions' in domainStatus and domainStatus['EBSOptions']['EBSEnabled']
        if is_ebs_enabled: 
            ebsOptions = domainStatus['EBSOptions']
            iops = "No Iops"
            if "Iops" in ebsOptions:
                iops = str(ebsOptions['Iops']) + " Iops"
            totalStorage = int(clusterConfig['InstanceCount']) * int(ebsOptions['VolumeSize']) * 1024   # Convert to MB
            logger.info(' '.join([self.domain, "EBS enabled:", str(ebsOptions['EBSEnabled']), "type:", str(ebsOptions['VolumeType']), "size (GB):", str(ebsOptions['VolumeSize']), str(iops), "Total storage (MB):", str(totalStorage)]))
            ebs = True
            es_freespace = float(int(float(totalStorage) * ES_FREESPACE_PERCENT))
        else:
            logger.warning(self.domain + " EBS not in use. Using instance storage only.")
            if clusterConfig['InstanceType'] in DISK_SPACE:
                es_freespace = DISK_SPACE[clusterConfig['InstanceType']] * 1024 * ES_FREESPACE_PERCENT * clusterConfig['InstanceCount']
                logger.info(' '.join([self.domain, "Instance storage definition found for:", DISK_SPACE[clusterConfig['InstanceType']], "GB; free storage calced to:", es_freespace, "MB"]))
            else:
                # InstanceType not found in DISK_SPACE. What's going on? (some instance types change to/from EBS, over time, it seems)
                logger.warning(self.domain + " " + str(clusterConfig['InstanceType']) + " is using instance storage, but definition of its disk space is not available.")

        logger.info(' '.join([self.domain, "Desired free storage set to (in MB):", str(es_freespace)])) 
        self.ebs = ebs
        self.es_freespace = es_freespace
        return es_freespace

def process_alarms(esclient, cwclient, espref, desiredEsFree, account, alarmActions):        
    ourDomains = get_domains_list(esclient, espref)
    # Now we've got the list 
    logger.info("List of Amazon Elasticsearch Service domains starting with given prefix (" + espref + "): " + ', '.join(ourDomains))

    # Now, get a list of the CloudWatch alarms, for each domain.
    # We could cut this list significantly if we knew the alarm-name-prefix would always be. But, we don't, right now.
    # TO DO: so ... given that ... add pagination, in case there's too many alarms.

    missingAlarms = 0
    okAlarms = 0
    notOkAlarms = 0
    esdomain = None
        
    for domain in ourDomains:
        # First: check the basic domain options against best practices  
        try:
            esdomain = ESDomain(esclient, domain, desiredEsFree, alarmActions)
        except Exception as e:
            # There may still be alarms defined.
            # So, carry on, check the default alarms for this cluster.
            logger.warning(domain + " " + str(e))
           
        esAlarms = esdomain.get_alarms()

        # Now, check the individual CloudWatch alarms
        # Unless you add the correct dimensions, the alarm will not correctly "connect" to the metric
        # How do you know what's correct? - at the bottom of http://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/es-metricscollected.html
        dimensions = [  {"Name": "DomainName", "Value": domain }, 
                        {"Name": "ClientId", "Value": str(account) }
                    ]  
        
        # Get the list of alarms that have been set. 
        for esAlarm in esAlarms:
            metricsList = cwclient.describe_alarms_for_metric(
                MetricName=esAlarm.metric,
                Namespace=ES_NAME_SPACE,
                Dimensions=dimensions                        
                )
            alarms = metricsList['MetricAlarms']
            # check the alarm(s) we got back, to make sure they're the ones we want.
            if len(alarms) < 1:
                logger.warning(domain + " Missing alarm: " + str(esAlarm))
                missingAlarms += 1
            else:
                for alarm in alarms:
                    okAlarm = True
                    alarm_checker = AlarmChecker(domain, alarm)
                    okAlarm = alarm_checker.check_statistics(esAlarm.stat) and \
                        alarm_checker.check_period(esAlarm.period) and \
                        alarm_checker.check_threshold(esAlarm.threshold) and \
                        alarm_checker.check_evalPeriod(esAlarm.evalPeriod) and \
                        alarm_checker.check_operator(esAlarm.operator) and \
                        alarm_checker.check_alarm_actions(esAlarm.alarmAction)        
                    if okAlarm:
                        logger.info(' '.join([domain, "Alarm definition matches:", alarm['MetricName'], alarm['AlarmName']]))
                        okAlarms += 1
                    else:
                        notOkAlarms += 1
    logger.info("=======================================================================================================")
    logger.info("Successfully finished processing!")
    logger.info("Alarm status summary: across " + str(len(ourDomains)) + " domains:")
    logger.info("    Ok alarms " + str(okAlarms))
    logger.info("    Missing alarms " + str(missingAlarms))
    logger.info("    Not matching alarms " + str(notOkAlarms))
    return

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

    try:
        global logger
        logger = init_logging()
        logger = set_log_level(logger, os.environ.get('log_level', 'INFO'))

        logger.debug("Running function lambda_handler")
        process_global_vars()

    except SystemExit:
        logger.error("Exiting")
        sys.exit(1)
    except ValueError:
        exit(1)
    except:
        print ("Unexpected error!\n Stack Trace:", traceback.format_exc())

    # Check environment variables
    espref = os.environ.get('esprefix', DEFAULT_DOMAIN_PREFIX)   
    desiredEsFree = os.environ.get('esfree', DEFAULT_ES_FREESPACE)
    account = boto3.client('sts').get_caller_identity().get('Account')
    AWS_REGION = os.environ.get('AWS_REGION', DEFAULT_REGION)
    esAlarmActions = os.environ.get('alarmActions', get_default_alarm_actions(AWS_REGION,account,DEFAULT_SNSTOPIC))
 
    # Establish credentials
    session_var = boto3.session.Session()
    credentials = session_var.get_credentials()
    esregion = session_var.region_name or DEFAULT_REGION
    esclient = boto3.client("es")
    cwclient = boto3.client("cloudwatch")

    process_alarms(esclient, cwclient, espref, desiredEsFree, account, esAlarmActions)
    return 'Success' 

def main():
    global logger
    logger = init_logging()
    os.environ['log_level'] = os.environ.get('log_level', "INFO")

    logger = setup_local_logging(logger, os.environ['log_level'])

    event = {'log_level': 'INFO'}
    os.environ['AWS_REGION'] = os.environ.get('AWS_REGION', DEFAULT_REGION)

    args = get_args()
    b3session = boto3.Session(profile_name=args.profile, region_name=args.region)
    
    esclient = b3session.client("es")
    cwclient = b3session.client("cloudwatch")
    process_alarms(esclient, cwclient, args.esprefix, args.free, args.account, args.notify)
    
# Standalone harness, to run the same checks from the command line    
if __name__ == "__main__":
    main()

    

